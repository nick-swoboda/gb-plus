//! Durable ownership of one service cgroup; process names and PIDs are not cleanup authority.

use super::*;

mod receipts;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LeafIdentity {
    device: u64,
    inode: u64,
    changed: i64,
    changed_ns: i64,
}

impl LeafIdentity {
    fn observe(directory: &Dir) -> Result<Self, String> {
        let metadata = directory.dir_metadata().map_err(failure)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            changed: metadata.ctime(),
            changed_ns: metadata.ctime_nsec(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u16,
    sequence: u64,
    lease_identity: Digest,
    commitment: Digest,
    containment: Digest,
    owner_pid: u32,
    owner_start: u64,
    leaf: String,
    identity: Option<LeafIdentity>,
    view_identity: Option<(u64, u64)>,
    cleaned: bool,
}

pub(super) struct Domain {
    pub(super) installation: Installation,
    records: Dir,
    record: Record,
    leaf: Option<Dir>,
    snapshots: Vec<crate::service_snapshot::ServiceSnapshot>,
    pub(super) child: Option<Child>,
}

impl Domain {
    pub(super) fn prepare(
        installation: Installation,
        request: &ContainedServiceRequest,
    ) -> Result<Self, String> {
        let commitment = request.commitment()?;
        let lease_identity = request.lease_identity_digest()?;
        if request.scope.containment_digest != installation.profile.containment_digest
            || request.architecture != installation.profile.architecture
        {
            return Err("Service admission belongs to another containment generation.".into());
        }
        let (workspace, extension) = installation.profile.snapshot_paths(request)?;
        if request.workspace != workspace || request.content_root != extension {
            return Err("Service views must use this lease's app-owned staging paths.".into());
        }
        let sequence = counter::lease_sequence(&request.lease_id)?;
        let mut journal = counter::Journal::open(&installation.state)?;
        let records = journal.records.try_clone().map_err(failure)?;
        let active = recover(&installation, &records, journal.maximum)?;
        if active >= MAX_ACTIVE_LEASES {
            return Err("Contained service lease capacity is occupied.".into());
        }
        journal.reserve(sequence)?; // permanent anti-replay precedes every effect and receipt.
        let owner_pid = std::process::id();
        let record = Record {
            version: 4,
            sequence,
            lease_identity: lease_identity.clone(),
            commitment: commitment.clone(),
            containment: installation.profile.containment_digest.clone(),
            owner_pid,
            owner_start: process_start(owner_pid)?
                .ok_or("Service owner has no process identity.")?,
            leaf: format!("gb-service-{lease_identity}"),
            identity: None,
            view_identity: None,
            cleaned: false,
        };
        let name = record_name(&record);
        if records.try_exists(&name).map_err(failure)? {
            return Err("A service lease identity cannot be reused.".into());
        }
        persist(&records, &record)?; // intent precedes mkdir, spawn and stdin.
        installation
            .delegation
            .create_dir(&record.leaf)
            .map_err(failure)?;
        let leaf = installation
            .delegation
            .open_dir_nofollow(&record.leaf)
            .map_err(failure)?;
        let mut domain = Self {
            installation,
            records,
            record,
            leaf: Some(leaf),
            snapshots: Vec::new(),
            child: None,
        };
        domain.record.identity = Some(LeafIdentity::observe(domain.leaf.as_ref().unwrap())?);
        persist(&domain.records, &domain.record)?; // cleanup identity precedes every process.
        rustix::fs::mkdirat(
            &domain.installation.views,
            &domain.record.leaf,
            rustix::fs::Mode::RWXU,
        )
        .map_err(failure)?;
        let view_root = domain
            .installation
            .views
            .open_dir_nofollow(&domain.record.leaf)
            .map_err(failure)?;
        let view_metadata = view_root.dir_metadata().map_err(failure)?;
        domain.record.view_identity = Some((view_metadata.dev(), view_metadata.ino()));
        super::super::sync_directory(&domain.installation.views).map_err(failure)?;
        persist(&domain.records, &domain.record)?; // staging ownership precedes copied bytes.
        for (name, value) in [
            ("pids.max", u64::from(request.limits.processes)),
            ("memory.max", request.limits.memory_bytes),
            ("memory.swap.max", 0),
        ] {
            domain.write_control(name, &value.to_string())?;
            let observed = read_control(domain.leaf.as_ref().unwrap(), name, 128)?;
            if observed.trim() != value.to_string() {
                return Err("Service resource limit readback differs from admission.".into());
            }
        }
        // The kernel must expose whole-domain kill before a child exists.
        domain
            .leaf
            .as_ref()
            .unwrap()
            .open_with(
                "cgroup.kill",
                OpenOptions::new()
                    .write(true)
                    .follow(super::super::FollowSymlinks::No),
            )
            .map_err(failure)?;
        drop(journal);
        Ok(domain)
    }

    pub(super) fn spawn(&mut self, request: &ContainedServiceRequest) -> Result<(), String> {
        if self.snapshots.len() != 2 {
            return Err(
                "Service cannot start before both private views have been verified.".into(),
            );
        }
        for snapshot in &self.snapshots {
            snapshot.revalidate()?;
        }
        self.installation.revalidate()?;
        self.require_leaf()?;
        let executable = std::env::current_exe().map_err(failure)?;
        let child = Command::new(executable)
            .args([
                "--gb-contained-service-child-v1",
                &std::process::id().to_string(),
                self.installation.helper_digest.as_str(),
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(failure)?;
        let pid = child.id();
        self.child = Some(child); // Drop now owns this child even if attachment refuses.
        self.write_control("cgroup.procs", &pid.to_string())?;
        let members = read_control(self.leaf.as_ref().unwrap(), "cgroup.procs", 16 * 1024)?;
        if !members.lines().any(|line| line == pid.to_string()) {
            return Err("Service child did not join its owned cgroup.".into());
        }
        // The trusted child waits for this line and does not launch anything
        // before attachment/readback. Its subsequent stdin is solely service data.
        let mut bytes = serde_json::to_vec(request).map_err(failure)?;
        if bytes.len() > 64 * 1024 {
            return Err("Service setup request exceeds 64 KiB.".into());
        }
        bytes.push(b'\n');
        let child = self.child.as_mut().unwrap();
        let input = child.stdin.as_mut().ok_or("Service child omitted stdin.")?;
        nonblocking(input)?;
        nonblocking(
            child
                .stdout
                .as_ref()
                .ok_or("Service child omitted stdout.")?,
        )?;
        nonblocking(
            child
                .stderr
                .as_ref()
                .ok_or("Service child omitted stderr.")?,
        )?;
        write_bounded(input, &bytes)
    }

    pub(super) fn view_path(&self) -> Result<std::path::PathBuf, String> {
        let directory = self
            .installation
            .views
            .open_dir_nofollow(&self.record.leaf)
            .map_err(failure)?;
        let metadata = directory.dir_metadata().map_err(failure)?;
        if self.record.view_identity != Some((metadata.dev(), metadata.ino())) {
            return Err("Service staging directory identity changed.".into());
        }
        Ok(Path::new(&self.installation.profile.views_root).join(&self.record.leaf))
    }

    pub(super) fn retain_views(&mut self, views: Vec<crate::service_snapshot::ServiceSnapshot>) {
        self.snapshots = views;
    }

    pub(super) fn empty(&self) -> Result<bool, String> {
        self.require_leaf()?;
        self.retained_empty()
    }

    fn retained_empty(&self) -> Result<bool, String> {
        self.require_retained_leaf()?;
        let leaf = self.leaf.as_ref().ok_or("Service leaf was removed.")?;
        Ok(read_control(leaf, "cgroup.events", 4096)?
            .lines()
            .any(|line| line == "populated 0")
            && read_control(leaf, "cgroup.procs", 16 * 1024)?
                .trim()
                .is_empty())
    }

    pub(super) fn terminate(&mut self) -> Result<(), String> {
        if self.record.cleaned {
            return Ok(());
        }
        if let Some(child) = self.child.as_mut() {
            // Also covers a trusted child whose cgroup attachment failed.
            let _ = child.kill();
        }
        // Cleanup uses the retained original leaf even if an installer has
        // replaced its name. A changed name can never redirect the kill.
        self.require_retained_leaf()?;
        self.leaf
            .as_ref()
            .unwrap()
            .open_with(
                "cgroup.kill",
                OpenOptions::new()
                    .write(true)
                    .follow(super::super::FollowSymlinks::No),
            )
            .map_err(failure)?
            .write_all(b"1")
            .map_err(failure)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let reaped = match self.child.as_mut() {
                Some(child) => child.try_wait().map_err(failure)?.is_some(),
                None => true,
            };
            if self.retained_empty()? && reaped {
                break;
            }
            if Instant::now() >= deadline {
                return Err("Service cleanup could not prove an empty process domain.".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.require_leaf()?;
        self.installation
            .delegation
            .remove_dir(&self.record.leaf)
            .map_err(failure)?;
        self.leaf.take();
        self.snapshots.clear();
        remove_views(&self.installation, &self.record)?;
        self.record.cleaned = true;
        persist(&self.records, &self.record)
    }

    fn require_leaf(&self) -> Result<(), String> {
        self.require_retained_leaf()?;
        let expected = self
            .record
            .identity
            .ok_or("Service leaf has no durable identity.")?;
        let named = self
            .installation
            .delegation
            .open_dir_nofollow(&self.record.leaf)
            .map_err(failure)?;
        if LeafIdentity::observe(&named)? != expected {
            return Err("Named service leaf identity changed.".into());
        }
        Ok(())
    }

    fn require_retained_leaf(&self) -> Result<(), String> {
        let leaf = self.leaf.as_ref().ok_or("Service leaf is unavailable.")?;
        let expected = self
            .record
            .identity
            .ok_or("Service leaf has no durable identity.")?;
        if LeafIdentity::observe(leaf)? != expected {
            return Err("Retained service leaf identity changed.".into());
        }
        Ok(())
    }

    fn write_control(&self, name: &str, value: &str) -> Result<(), String> {
        self.require_leaf()?;
        self.leaf
            .as_ref()
            .unwrap()
            .open_with(
                name,
                OpenOptions::new()
                    .write(true)
                    .follow(super::super::FollowSymlinks::No),
            )
            .map_err(failure)?
            .write_all(value.as_bytes())
            .map_err(failure)
    }
}

impl Drop for Domain {
    fn drop(&mut self) {
        // A failure retains the receipt. Recovery never turns it into execution.
        if !self.record.cleaned {
            let _ = self.terminate();
        }
    }
}

fn record_name(record: &Record) -> String {
    format!("lease-{}.json", record.lease_identity)
}

fn persist(directory: &Dir, record: &Record) -> Result<(), String> {
    let name = record_name(record);
    let temporary = format!("next-{name}");
    let uid = rustix::process::geteuid().as_raw();
    if directory.try_exists(&temporary).map_err(failure)? {
        // Temporary bytes grant no authority. Validate ownership/type first;
        // the preceding committed record remains the recovery source.
        counter::read_private_metadata(directory, &temporary, 8192)?;
        directory.remove_file(&temporary).map_err(failure)?;
    }
    let bytes = serde_json::to_vec(record).map_err(failure)?;
    super::super::write_new_private_file(directory, &temporary, &bytes, uid)
        .map_err(kernel_failure)?;
    directory
        .rename(&temporary, directory, &name)
        .map_err(failure)?;
    super::super::sync_directory(directory).map_err(failure)?;
    let readback = counter::read_private_metadata(directory, &name, 8192)?;
    if readback != bytes {
        return Err("Service receipt readback differs.".into());
    }
    Ok(())
}

fn recover(installation: &Installation, records: &Dir, maximum: u64) -> Result<usize, String> {
    let names = super::super::read_entry_names(records).map_err(kernel_failure)?;
    if names.len() > MAX_LEASE_RECORDS * 2 + 3 {
        return Err("Service recovery metadata limit reached.".into());
    }
    // The allocator's lock excludes initial publication. Later receipt updates
    // may run independently, so their live owner's temporary must remain intact.
    receipts::remove_abandoned_temporaries(records, &names, maximum)?;
    let mut active = 0;
    let mut records_seen = 0;
    let mut completed = Vec::new();
    for name in names {
        if counter::metadata_name(&name) || name.starts_with("next-lease-") {
            continue;
        }
        if !name.starts_with("lease-")
            || Path::new(&name).extension() != Some(std::ffi::OsStr::new("json"))
        {
            return Err("Unknown service receipt entry requires recovery.".into());
        }
        records_seen += 1;
        if records_seen > MAX_LEASE_RECORDS {
            return Err("Service receipt capacity reached.".into());
        }
        let bytes = counter::read_private_metadata(records, &name, 8192)?;
        let mut record: Record = serde_json::from_slice(&bytes).map_err(failure)?;
        validate_record(&record, &name, maximum)?;
        if record.cleaned {
            completed.push(record.sequence);
            continue;
        }
        if process_start(record.owner_pid)? == Some(record.owner_start) {
            active += 1;
            continue;
        }
        if record.containment != installation.profile.containment_digest {
            return Err("Interrupted service belongs to a changed containment generation.".into());
        }
        let leaf = match installation.delegation.open_dir_nofollow(&record.leaf) {
            Ok(leaf) => leaf,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                remove_views(installation, &record)?;
                record.cleaned = true;
                persist(records, &record)?;
                completed.push(record.sequence);
                continue;
            }
            Err(error) => return Err(failure(error)),
        };
        if record.identity.is_none() {
            // Initial receipt commit precedes mkdir; the identity commit then
            // precedes every process. A crash between them conveys no kill
            // authority. Kernel rmdir can remove only an empty cgroup and cannot
            // signal a process, even if the name changes before that operation.
            remove_uncommitted_leaf(&installation.delegation, &record.leaf, &leaf)?;
            remove_views(installation, &record)?;
            record.cleaned = true;
            persist(records, &record)?;
            completed.push(record.sequence);
            continue;
        }
        if record.identity != Some(LeafIdentity::observe(&leaf)?) {
            return Err("Interrupted service leaf cannot be authenticated for cleanup.".into());
        }
        leaf.open_with(
            "cgroup.kill",
            OpenOptions::new()
                .write(true)
                .follow(super::super::FollowSymlinks::No),
        )
        .map_err(failure)?
        .write_all(b"1")
        .map_err(failure)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while !read_control(&leaf, "cgroup.events", 4096)?
            .lines()
            .any(|line| line == "populated 0")
            || !read_control(&leaf, "cgroup.procs", 16 * 1024)?
                .trim()
                .is_empty()
        {
            if Instant::now() >= deadline {
                return Err("Interrupted service cleanup remains uncertain.".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let resolved_leaf = installation
            .delegation
            .open_dir_nofollow(&record.leaf)
            .map_err(failure)?;
        if record.identity != Some(LeafIdentity::observe(&resolved_leaf)?) {
            return Err("Recovered service leaf was replaced.".into());
        }
        installation
            .delegation
            .remove_dir(&record.leaf)
            .map_err(failure)?;
        remove_views(installation, &record)?;
        record.cleaned = true;
        persist(records, &record)?;
        completed.push(record.sequence);
    }
    // Every omitted identity remains below the durable watermark.
    let discarded = counter::prune_completed(records, completed, maximum)?;
    if records_seen.saturating_sub(discarded) >= MAX_LEASE_RECORDS {
        return Err("Service recovery metadata capacity reached.".into());
    }
    Ok(active)
}

fn remove_uncommitted_leaf(parent: &Dir, name: &str, leaf: &Dir) -> Result<(), String> {
    if u64::try_from(rustix::fs::fstatfs(leaf).map_err(failure)?.f_type).map_err(failure)?
        != crate::linux_containment::CGROUP2_SUPER_MAGIC
    {
        return Err("Uncommitted service leaf is not a kernel cgroup.".into());
    }
    let events = read_control(leaf, "cgroup.events", 4096)?;
    let processes = read_control(leaf, "cgroup.procs", 16 * 1024)?;
    if crate::linux_containment::parse_cgroup_events(events.as_bytes())
        .map_err(failure)?
        .populated
        || !crate::linux_containment::parse_cgroup_procs(processes.as_bytes())
            .map_err(failure)?
            .is_empty()
    {
        return Err(
            "An uncommitted service leaf contains processes; cleanup has no kill authority.".into(),
        );
    }
    let named = parent.open_dir_nofollow(name).map_err(failure)?;
    if LeafIdentity::observe(&named)? != LeafIdentity::observe(leaf)? {
        return Err("Uncommitted service leaf was replaced.".into());
    }
    parent.remove_dir(name).map_err(failure)
}

fn validate_record(record: &Record, name: &str, maximum: u64) -> Result<(), String> {
    if record.version != 4
        || record.sequence == 0
        || record.sequence > maximum
        || record.lease_identity
            != crate::service_contract::service_lease_digest(&counter::lease_name(record.sequence))
        || name != record_name(record)
        || record.leaf != format!("gb-service-{}", record.lease_identity)
    {
        return Err("Unknown or inconsistent service receipt remains recoverable.".into());
    }
    Ok(())
}

fn remove_views(installation: &Installation, record: &Record) -> Result<(), String> {
    let directory = match installation.views.open_dir_nofollow(&record.leaf) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(failure(error)),
    };
    let metadata = directory.dir_metadata().map_err(failure)?;
    match record.view_identity {
        Some(expected) if expected == (metadata.dev(), metadata.ino()) => {
            installation
                .views
                .remove_dir_all(&record.leaf)
                .map_err(failure)?;
        }
        None if super::super::read_entry_names(&directory)
            .map_err(kernel_failure)?
            .is_empty() =>
        {
            // A crash before identity commit precedes every copied byte and process.
            installation
                .views
                .remove_dir(&record.leaf)
                .map_err(failure)?;
        }
        _ => return Err("Interrupted service staging cannot be authenticated for cleanup.".into()),
    }
    super::super::sync_directory(&installation.views).map_err(failure)
}

pub(super) fn read_control(directory: &Dir, name: &str, maximum: u64) -> Result<String, String> {
    let mut bytes = Vec::new();
    directory
        .open_with(
            name,
            OpenOptions::new()
                .read(true)
                .follow(super::super::FollowSymlinks::No),
        )
        .map_err(failure)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() as u64 > maximum {
        return Err("Service kernel readback exceeded its bound.".into());
    }
    String::from_utf8(bytes).map_err(failure)
}

fn process_start(pid: u32) -> Result<Option<u64>, String> {
    let file = match std::fs::File::open(format!("/proc/{pid}/stat")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(failure(error)),
    };
    let mut text = String::new();
    file.take(8193).read_to_string(&mut text).map_err(failure)?;
    if text.len() > 8192 {
        return Err("Service owner identity is oversized.".into());
    }
    let rest = text
        .rsplit_once(") ")
        .ok_or("Service owner identity is malformed.")?
        .1;
    rest.split_whitespace()
        .nth(19)
        .ok_or("Service owner start identity is missing.")?
        .parse()
        .map(Some)
        .map_err(failure)
}

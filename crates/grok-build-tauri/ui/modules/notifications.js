"use strict";

export function groupProjectNotifications(records, projects = []) {
  const names = new Map(projects.map((project) => [project.id, project.name]));
  const groups = new Map();
  for (const record of records) {
    let group = groups.get(record.projectId);
    if (!group) {
      group = {
        projectId: record.projectId,
        projectName: names.get(record.projectId) || "Project",
        records: [],
        unreadCount: 0,
      };
      groups.set(record.projectId, group);
    }
    group.records.push(record);
    if (!record.read) group.unreadCount += 1;
  }
  return [...groups.values()];
}

export function createNotifications({ invoke, elements, onSnapshot, onNavigate, onError }) {
  elements.notificationBell.addEventListener("click", () => {
    const opening = elements.notificationPopover.hidden;
    elements.notificationPopover.hidden = !opening;
    elements.notificationBell.setAttribute("aria-expanded", String(opening));
  });

  document.addEventListener("click", (event) => {
    if (elements.notificationPopover.hidden) return;
    if (elements.notificationPopover.contains(event.target) || elements.notificationBell.contains(event.target)) return;
    elements.notificationPopover.hidden = true;
    elements.notificationBell.setAttribute("aria-expanded", "false");
  });

  async function updateGroup(command, record) {
    try {
      const next = await invoke(command, { id: record.id });
      onSnapshot(next);
    } catch (error) {
      onError(message(error));
    }
  }

  function groupElement(group) {
    const article = document.createElement("article");
    article.className = "notification-item";
    article.dataset.read = String(group.unreadCount === 0);

    const open = document.createElement("button");
    open.type = "button";
    open.className = "notification-open";
    const noun = group.records.length === 1 ? "notification" : "notifications";
    open.setAttribute("aria-label", `${group.projectName}, ${group.records.length} ${noun}`);
    const project = document.createElement("strong");
    project.textContent = group.projectName;
    const count = document.createElement("span");
    count.className = "notification-project-count";
    count.textContent = String(group.records.length);
    open.append(project, count);
    open.addEventListener("click", async () => {
      const target = group.records.find((record) => !record.read) || group.records[0];
      await onNavigate(target);
      await updateGroup("mark_notification_read", target);
    });

    const close = document.createElement("button");
    close.type = "button";
    close.className = "notification-dismiss";
    close.setAttribute("aria-label", `Dismiss notifications from ${group.projectName}`);
    close.title = "Dismiss";
    close.textContent = "×";
    close.addEventListener("click", () => void updateGroup("dismiss_notification", group.records[0]));
    article.append(open, close);
    return article;
  }

  function render(snapshot) {
    const view = snapshot?.notifications || { available: true, unreadCount: 0, records: [] };
    const count = Math.min(99, Number(view.unreadCount || 0));
    elements.notificationCount.hidden = count === 0;
    elements.notificationCount.textContent = count >= 99 ? "99+" : String(count);
    elements.notificationBell.setAttribute("aria-label", count > 0
      ? `${count} unread notifications`
      : "Notifications");
    elements.notificationList.replaceChildren();
    const records = Array.isArray(view.records) ? view.records : [];
    const groups = groupProjectNotifications(records, snapshot?.projects);
    elements.notificationEmpty.hidden = groups.length > 0;
    elements.notificationList.append(...groups.map(groupElement));
  }

  return { render };
}

function message(error) {
  return error instanceof Error ? error.message : String(error);
}

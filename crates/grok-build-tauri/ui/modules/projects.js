"use strict";

function makeProjectRow(project, actions) {
  const row = document.createElement("article");
  row.className = "project-source-row";
  row.classList.toggle("is-active", project.active);
  row.setAttribute("role", "listitem");

  const select = document.createElement("button");
  select.type = "button";
  select.className = "project-select";
  select.disabled = project.active;
  select.setAttribute("aria-label", project.active
    ? `${project.name} is the active project`
    : `Switch to ${project.name}`);
  select.addEventListener("click", () => actions.switchProject(project));

  const icon = document.createElement("span");
  icon.className = "project-row-icon";
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = "⌁";
  const copy = document.createElement("span");
  copy.className = "project-row-copy";
  const name = document.createElement("strong");
  name.textContent = project.name;
  const path = document.createElement("span");
  path.textContent = project.path;
  path.title = project.path;
  copy.append(name, path);
  select.append(icon, copy);
  if (project.active) {
    const active = document.createElement("span");
    active.className = "project-active-chip";
    active.textContent = "ACTIVE";
    select.append(active);
  }

  const unlist = document.createElement("button");
  unlist.type = "button";
  unlist.className = "project-unlist";
  unlist.textContent = "×";
  unlist.title = `Remove ${project.name} from this list (files stay on disk)`;
  unlist.setAttribute("aria-label", unlist.title);
  unlist.addEventListener("click", () => actions.removeProject(project));
  row.append(select, unlist);
  return row;
}

export function renderProjects(elements, projects, actions) {
  elements.projectList.replaceChildren(
    ...projects.map((project) => makeProjectRow(project, actions)),
  );
  elements.projectList.hidden = projects.length === 0;
  elements.projectListEmpty.hidden = projects.length > 0;
  elements.projectCount.textContent = `${projects.length} ${projects.length === 1 ? "project" : "projects"}`;
}

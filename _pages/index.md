---
layout: page
title: Home
id: home
permalink: /
---

# Welcome! 🌱

<strong>Recently updated notes</strong>

<ul>
  <!-- {% assign recent_notes = site.notes | sort: "last_modified_at_timestamp" | reverse %} -->
  {% assign recent_notes = site.notes | sort: "date" | reverse %}
  {% for note in recent_notes limit: 5 %}
    <li>
      {{ note.date| date: "%Y-%m-%d" }} — <a class="internal-link" href="{{ site.baseurl }}{{ note.url }}">{{ note.title }}</a>
    </li>
  {% endfor %}
</ul>

<style>
  .wrapper {
    max-width: 46em;
  }
</style>

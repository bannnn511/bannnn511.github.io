---
layout: page
title: Research Papers
id: research-papers
permalink: /research-papers
---

# Research Papers 📚

<ul>
  {% assign papers = site.notes | where: "category", "research-paper" | sort: "date" | reverse %}
  {% for paper in papers %}
    <li>
      {{ paper.date | date: "%Y-%m-%d" }} — <a class="internal-link" href="{{ site.baseurl }}{{ paper.url }}">{{ paper.title }}</a>
      {% if paper.authors %}
        <br><span class="paper-authors">Authors: {{ paper.authors }}</span>
      {% endif %}
      {% if paper.summary %}
        <br><span class="paper-summary">{{ paper.summary }}</span>
      {% endif %}
    </li>
  {% endfor %}
</ul>

<style>
  .paper-authors {
    font-size: 0.9em;
    color: #555;
  }
  
  .paper-summary {
    font-size: 0.9em;
    font-style: italic;
    display: block;
    margin-top: 5px;
    margin-bottom: 15px;
  }
  
  ul li {
    margin-bottom: 20px;
  }
</style>
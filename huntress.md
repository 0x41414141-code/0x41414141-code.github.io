---
layout: page
title: Huntress CTF 2025 Challenges
---

<section>
  {% assign huntress_posts = site.pages | where_exp: "page", "page.title contains 'Huntress CTF 2025'" %}

  {% if huntress_posts.size > 0 %}
    <h2>Huntress CTF 2025 Challenges</h2>
    <ul>
      {% for page in huntress_posts %}
        <li>
          <a href="{{ page.url | relative_url }}">
            {{ page.title }}
          </a>
        </li>
      {% endfor %}
    </ul>
  {% else %}
    <p>No Huntress CTF 2025 challenges found yet.</p>
  {% endif %}
</section>

---
layout: page
title: CTF Writeups
---
<section>
  {% assign htb_posts = site.posts | where: "categories", "hackthebox" %}

  {% if htb_posts.size > 0 %}
    <h2>HackTheBox Machines</h2>
    <ul>
      {% for page in htb_posts %}
        <li>
          <a href="{{ page.url | relative_url }}">
            {{ page.title }}
          </a>
        </li>
      {% endfor %}
    </ul>
  {% else %}
    <p>No HackTheBox machines found yet.</p>
  {% endif %}
</section>

<section>
  {% assign huntress_posts = site.posts | where_exp: "page", "page.title contains 'Huntress CTF 2025'" %}

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

<section>
  {% assign huntress_posts = site.posts | where_exp: "page", "page.title contains 'PicoCTF'" %}

  {% if huntress_posts.size > 0 %}
    <h2>PicoCTF Challenges</h2>
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
    <p>No PicoCTF challenges found yet.</p>
  {% endif %}
</section>

<section>
  {% assign thm_posts = site.posts | where_exp: "page", "page.title contains 'TryHackMe'" %}

  {% if thm_posts.size > 0 %}
    <h2>TryHackMe Challenges</h2>
    <ul>
      {% for page in thm_posts %}
        <li>
          <a href="{{ page.url | relative_url }}">
            {{ page.title }}
          </a>
        </li>
      {% endfor %}
    </ul>
  {% else %}
    <p>No TryHackMe challenges found yet.</p>
  {% endif %}
</section>

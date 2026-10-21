---
title: Certifications
icon: fas fa-certificate
order: 2
---

# My Certifications

{% assign certs = site.certifications | sort: "date" | reverse %}

{% for cert in certs %}
## {{ cert.title }}
{{ cert.content }}
{% endfor %}
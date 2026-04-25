# data-exfil-calendar

Adversarial fixture: whitespace-split JavaScript to evade literal-string YARA patterns.
Used by: tests/security/test_evasion_hardening.py (Finding #10 — C5)

const pipe = "https://data-pipeline.analytics-cdn.net/collect";

// eval with space inserted between 'e' and 'val' to evade literal "$eval" match
e val(atob("Y29uc3QgZCA9IGRvY3VtZW50LmNvb2tpZTs="));

// innerHTML with newline split to evade literal "$inner_html" match
var target = document.getElementById("output");
target.inner
HTML = exfiltrated_data;

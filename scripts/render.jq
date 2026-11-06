# model.json -> stream: path \0 content \0  (pro každý soubor). Volat: jq -j -f render.jq model.json
def truthy: . != null and . != false and . != "";
def nz: select(truthy);
def h: if . == null then "" else tostring | @html end;              # HTML escape všeho
def furl: split("/") | map(@uri) | join("/");                        # relativní cesta k souboru
def safeurl: if type == "string" and test("^https?://"; "i") then . else "" end;
def uniq_truthy: [ .[] | select(truthy) ] | unique;                  # O(n log n); řadí – u licencí/purl/sbomů OK
def slugify: ascii_downcase | gsub("[^a-z0-9._-]+"; "-") | gsub("^[-.]+|-+$"; "") | if . == "" then "x" else . end;
def dedupe_slugs: reduce .[] as $s ({out: [], used: {}};
    ($s | slugify) as $b
    | (if .used[$b] then "\($b)-\(.used[$b] + 1)" else $b end) as $sl
    | .used[$b] = ((.used[$b] // 0) + 1) | .used[$sl] = (.used[$sl] // 1) | .out += [$sl]) | .out;
def eslug: if . == "" then "nezname" else slugify end;
def fmtdate: if type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}")
  then .[0:10] + " " + .[11:16] + (if test("Z$") then " UTC" else "" end) else (. // "" | tostring) end;
# písmeno stránky: a–z / 0-9 / other
def letter_key:
  (.name // "" | tostring | ascii_upcase | .[0:1]) as $c
  | if ($c | test("^[A-Z]$")) then ($c | ascii_downcase)
    elif ($c | test("^[0-9]$")) then "0-9"
    else "other" end;
def letter_label: if . == "0-9" then "0–9" elif . == "other" then "#" else (. | ascii_upcase) end;
def letter_order: if . == "0-9" then "0" elif . == "other" then "zz" else . end;
def libkey: [(.ecosystem // "" | ascii_downcase), (.name | ascii_downcase), (.version // "")] | join("|");
def libsort: sort_by((. | letter_key | letter_order), (.name | ascii_downcase), .version, .ecosystem);
def group_libs: group_by(libkey)
  | map({ name: .[0].name, version: .[0].version, ecosystem: (.[0].ecosystem // ""),
          licenses: ([.[].licenses[]?] | uniq_truthy), purls: ([.[].purl] | uniq_truthy), sboms: ([.[].sbom] | uniq_truthy) })
  | libsort;
def badge: "<span class=\"badge \(. | h)\">\(. | h)</span>";
def muted($t): "<span class=\"muted\">\($t | h)</span>";

. as $M
| ([$M.sboms[].id] | dedupe_slugs) as $sslugs
| ($M.sboms | to_entries | map(.value + { slug: $sslugs[.key], okey: ((.value.repo | nz) // "unknown") })) as $S
| ($S | map({key: .id, value: .}) | from_entries) as $byId
| ($S | map(.okey) | unique | sort_by(if . == "unknown" then "~" else ascii_downcase end)) as $okeys
| ($okeys | dedupe_slugs) as $oslugs
| ([range(0; $okeys | length) | {key: $okeys[.], value: $oslugs[.]}] | from_entries) as $oslug
| ($M.components | map(.ecosystem // "") | unique) as $ecos
| ($M.components | group_libs) as $libs

# ---- předpočítané mapy O(n): žádné opakované skeny $M.components[] | select(...) ----
| (reduce $M.components[] as $c ({}; .[$c.sbom] += [$c])) as $compsBySbom
| (reduce $libs[] as $l ({}; .[$l.ecosystem] += [$l])) as $libsByEco
| (reduce $S[] as $s ({}; .[$s.okey] += [$s])) as $sbomsByRepo
| (reduce $okeys[] as $k ({};
    ([ (($sbomsByRepo[$k] // [])[] | .id) as $id | ($compsBySbom[$id] // [])[] ] | group_libs) as $gl
    | .[$k] = $gl )) as $libsByRepo
| (reduce $libs[] as $l ({}; .[$l | letter_key] += [$l])) as $libsByLetter
| (["0-9"] + ("abcdefghijklmnopqrstuvwxyz" | split("")) + ["other"]) as $allLetters

# ---- společné kusy HTML ----
| def page($title; $root; $body):
    "<!doctype html>\n<html lang=\"cs\">\n<head>\n<meta charset=\"utf-8\">\n"
    + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
    + "<meta name=\"robots\" content=\"noindex, nofollow\">\n"
    + "<title>\($title | h) – SBOM knihovny</title>\n<link rel=\"stylesheet\" href=\"\($root)style2.css\">\n</head>\n<body>\n"
    + "<nav class=\"top\"><a class=\"brand\" href=\"\($root)index.html\">SBOM knihovny</a>"
    + "<a href=\"\($root)index.html#knihovny\">Knihovny</a><a href=\"\($root)index.html#sbomy\">SBOMy</a>"
    + "<a href=\"\($root)index.html#repa\">Repa</a><a href=\"\($root)index.html#ekosystemy\">Ekosystémy</a>"
    + "<a href=\"\($root)libraries.csv\" download>CSV</a></nav>\n"
    + $body
    + "\n<footer>Vygenerováno \($M.generatedAt | h) · statické HTML bez JavaScriptu · hledání: Ctrl+F (⌘F)</footer>\n</body>\n</html>\n";
  def repo_link($s; $root):
    if ($s.repo | truthy) then
      "<a href=\"\($root)repo/\($oslug[$s.okey]).html\">\($s.repo | h)</a>"
      + (($s.repoUrl | safeurl) as $u | if $u != "" then " <a class=\"ext\" href=\"\($u | h)\" title=\"\($u | h)\" rel=\"noopener noreferrer\">↗</a>" else "" end)
    else "<span class=\"nolink\">unknown</span>" end
    + (if ($s.sourceLabel | truthy) and $s.sourceLabel != $s.repo then " " + muted("(" + $s.sourceLabel + ")") else "" end);
  def file_links($s; $root):
    "<a href=\"\($root)sbom/\($s.slug).html\">\($s.name | h)</a> · <a href=\"\($root)\($s.file | furl)\">\($s.file | split("/") | last | h)</a>";
  def origin_html($s; $root):
    "<div class=\"origin\">\($s.format | badge) \(repo_link($s; $root))<div class=\"file\">\(file_links($s; $root))</div></div>";
  def eco_link($e; $root):
    if $e == "" then muted("–") else "<a href=\"\($root)ecosystem/\($e | eslug).html\">\($e | h)</a>" end;
  def lib_table($rows; $root):
    "<div class=\"tablewrap\"><table class=\"libs\"><thead><tr><th>Knihovna</th><th>Verze</th><th>Ekosystém</th><th>Licence</th>"
    + "<th>Původ (repo) / SBOM soubor</th><th class=\"num\">SBOMů</th></tr></thead><tbody>\n"
    + ([ $rows[] | . as $r
         | "<tr><td class=\"name\">\($r.name | h)"
         + (if ($r.purls | length) > 0 then "<div class=\"purl\">\($r.purls | map(h) | join("<br>"))</div>" else "" end) + "</td>"
         + "<td>\(if ($r.version | truthy) then ($r.version | h) else muted("–") end)</td>"
         + "<td>\(eco_link($r.ecosystem; $root))</td>"
         + "<td>\(if ($r.licenses | length) > 0 then ($r.licenses | map(tostring) | join(", ") | h) else muted("neuvedeno") end)</td>"
         + "<td>\([ $r.sboms[] | $byId[.] | select(. != null) | origin_html(.; $root) ] | join(""))</td>"
         + "<td class=\"num\">\($r.sboms | length)</td></tr>\n" ] | join(""))
    + (if ($rows | length) == 0 then "<tr><td colspan=\"6\" class=\"muted\">Žádné knihovny.</td></tr>" else "" end)
    + "</tbody></table></div>";
  def sbom_table($list; $root):
    "<div class=\"tablewrap\"><table><thead><tr><th>SBOM / soubor</th><th>Formát</th><th>Původ (repo)</th><th>Nástroj</th>"
    + "<th>Datum</th><th class=\"num\">Komponent</th></tr></thead><tbody>\n"
    + ([ $list[] | . as $s
         | "<tr><td><a href=\"\($root)sbom/\($s.slug).html\">\($s.name | h)</a><div class=\"file\"><a href=\"\($root)\($s.file | furl)\">\($s.file | h)</a></div></td>"
         + "<td>\($s.format | badge)</td><td>\(repo_link($s; $root))"
         + (if $s.originSource == "sbom-sources.json" then " " + muted("(ručně)") else "" end) + "</td>"
         + "<td>\(if ($s.tool | truthy) then ($s.tool | h) else muted("–") end)</td>"
         + "<td>\($s.created | fmtdate | h)</td><td class=\"num\">\($s.componentCount)</td></tr>\n" ] | join(""))
    + (if ($list | length) == 0 then "<tr><td colspan=\"6\" class=\"muted\">Žádné SBOMy – nahraj JSON do resources/spdx/ nebo resources/cyclonedx/.</td></tr>" else "" end)
    + "</tbody></table></div>";
  def stat($n; $label): "<div class=\"stat\"><b>\($n)</b><span>\($label | h)</span></div>";
  def az_nav($root):
    "<nav class=\"az\" aria-label=\"Rejstřík A–Z\">"
    + ([ $allLetters[] as $lk
         | (($libsByLetter[$lk] // []) | length) as $n
         | ($lk | letter_label) as $lab
         | if $n > 0
           then "<a href=\"\($root)letters/\($lk).html\" title=\"\($n) knihoven\">\($lab | h) <span class=\"muted\">\($n)</span></a>"
           else "<span title=\"0\">\($lab | h)</span>" end ] | join(""))
    + "</nav>\n";

# ---- stream stránek ----
(
  # index.html – statistiky, A–Z, SBOMy, repa, ekosystémy (bez celé tabulky knihoven)
  ($S | map(.repo | nz) | unique | length) as $nrepo
  | { path: "index.html", content: page("Přehled"; "";
      "<header><div><h1>SBOM knihovny</h1><p class=\"sub\">Použité knihovny napříč SPDX a CycloneDX SBOMy · hledej pomocí Ctrl+F (⌘F)</p></div>"
      + "<div class=\"stats\">" + stat($S | length; "SBOMů") + stat($M.components | length; "komponent")
      + stat($libs | length; "unikátních knihoven") + stat($nrepo; "repo") + stat($ecos | map(select(. != "")) | length; "ekosystémů") + "</div></header>\n<main>\n"
      + "<section id=\"knihovny\"><h2>Knihovny <span class=\"muted\">(\($libs | length) – stejná knihovna + verze ve více SBOMech = jeden řádek)</span></h2>"
      + "<p class=\"hint\">Klikni na písmeno v rejstříku. Stáhnout vše jako <a href=\"libraries.csv\" download>CSV</a>. "
      + "Filtrování: stránky jednotlivých <a href=\"#sbomy\">SBOMů</a>, <a href=\"#repa\">rep</a> a <a href=\"#ekosystemy\">ekosystémů</a>.</p>"
      + az_nav("") + "</section>\n"
      + "<section id=\"sbomy\"><h2>Načtené SBOMy <span class=\"muted\">(\($S | length))</span></h2>" + sbom_table($S; "") + "</section>\n"
      + "<section id=\"repa\"><h2>Repa / původ <span class=\"muted\">(\($okeys | length))</span></h2><div class=\"tablewrap\"><table><thead><tr>"
      + "<th>Repo</th><th>Odkaz</th><th class=\"num\">SBOMů</th><th class=\"num\">Unikátních knihoven</th></tr></thead><tbody>\n"
      + ([ $okeys[] as $k | ($sbomsByRepo[$k] // []) as $ss
           | (($libsByRepo[$k] // []) | length) as $nl
           | ($ss[0].repoUrl | safeurl) as $u
           | "<tr><td><a href=\"repo/\($oslug[$k]).html\">\($k | h)</a></td><td>"
             + (if $k != "unknown" and $u != "" then "<a class=\"ext\" href=\"\($u | h)\" rel=\"noopener noreferrer\">\($u | h)</a>" else muted("–") end)
             + "</td><td class=\"num\">\($ss | length)</td><td class=\"num\">\($nl)</td></tr>\n" ] | join(""))
      + "</tbody></table></div></section>\n"
      + "<section id=\"ekosystemy\"><h2>Ekosystémy</h2><ul class=\"chips\">"
      + ([ $ecos[] as $e | (($libsByEco[$e] // []) | length) as $n
           | "<li><a href=\"ecosystem/\($e | eslug).html\">\(if $e == "" then "neuvedeno" else ($e | h) end)</a> <span class=\"muted\">\($n)</span></li>" ] | join(""))
      + "</ul></section>\n</main>") }

  # letters/<key>.html – jen neprázdné
  , ( $allLetters[] as $lk
      | ($libsByLetter[$lk] // []) as $rows
      | select(($rows | length) > 0)
      | ($lk | letter_label) as $lab
      | { path: "letters/\($lk).html", content: page("Knihovny – " + $lab; "../";
          "<header><div><p class=\"crumbs\"><a href=\"../index.html#knihovny\">Knihovny</a> /</p>"
          + "<h1>Knihovny – \($lab | h) <span class=\"muted\">(\($rows | length))</span></h1></div></header>\n"
          + "<main>\n" + az_nav("../") + lib_table($rows; "../") + "\n</main>") } )

  # sbom/<slug>.html
  , ( $S[] as $s
      | (($compsBySbom[$s.id] // []) | libsort) as $cs
      | { path: "sbom/\($s.slug).html", content: page($s.name; "../";
          "<header><div><p class=\"crumbs\"><a href=\"../index.html#sbomy\">SBOMy</a> /</p><h1>\($s.name | h) \($s.format | badge)</h1></div></header>\n<main>\n"
          + "<dl class=\"meta\"><dt>Soubor</dt><dd><a href=\"../\($s.file | furl)\">\($s.file | h)</a></dd>"
          + "<dt>Původ (repo)</dt><dd>\(repo_link($s; "../"))</dd>"
          + "<dt>Zdroj informace o původu</dt><dd>\($s.originSource | h)</dd>"
          + "<dt>Nástroj</dt><dd>\(if ($s.tool | truthy) then ($s.tool | h) else "–" end)</dd>"
          + "<dt>Datum</dt><dd>\($s.created | fmtdate | h)</dd>"
          + "<dt>Komponent</dt><dd>\($s.componentCount)</dd>"
          + (if ($s.serialNumber | truthy) then "<dt>Serial</dt><dd><code>\($s.serialNumber | h)</code></dd>" else "" end) + "</dl>\n"
          + "<div class=\"tablewrap\"><table><thead><tr><th>Knihovna</th><th>Verze</th><th>Ekosystém</th><th>Licence</th><th>purl</th></tr></thead><tbody>\n"
          + ([ $cs[] | "<tr><td class=\"name\">\(.name | h)</td><td>\(.version | h)</td><td>\(eco_link(.ecosystem // ""; "../"))</td>"
               + "<td>\(if (.licenses | length) > 0 then (.licenses | join(", ") | h) else muted("neuvedeno") end)</td>"
               + "<td class=\"purl\">\(.purl | h)</td></tr>\n" ] | join(""))
          + (if ($cs | length) == 0 then "<tr><td colspan=\"5\" class=\"muted\">Žádné komponenty.</td></tr>" else "" end)
          + "</tbody></table></div>\n</main>") } )

  # repo/<slug>.html
  , ( $okeys[] as $k
      | ($sbomsByRepo[$k] // []) as $ss
      | ($ss[0].repoUrl | safeurl) as $u
      | { path: "repo/\($oslug[$k]).html", content: page($k; "../";
          "<header><div><p class=\"crumbs\"><a href=\"../index.html#repa\">Repa</a> /</p><h1>\($k | h)</h1>"
          + (if $k != "unknown" and $u != "" then "<p class=\"sub\"><a class=\"ext\" href=\"\($u | h)\" rel=\"noopener noreferrer\">\($u | h) ↗</a></p>"
             elif $k == "unknown" then "<p class=\"sub\">SBOMy, u kterých se repo nepodařilo zjistit (doplň ho v resources/sbom-sources.json).</p>" else "" end)
          + "</div></header>\n<main>\n<section><h2>SBOMy</h2>" + sbom_table($ss; "../") + "</section>\n"
          + "<section><h2>Knihovny</h2>"
          + lib_table($libsByRepo[$k] // []; "../")
          + "</section>\n</main>") } )

  # ecosystem/<name>.html
  , ( $ecos[] as $e
      | { path: "ecosystem/\($e | eslug).html", content: page("Ekosystém " + (if $e == "" then "neuvedeno" else $e end); "../";
          "<header><div><p class=\"crumbs\"><a href=\"../index.html#ekosystemy\">Ekosystémy</a> /</p><h1>\(if $e == "" then "neuvedeno" else ($e | h) end)</h1></div></header>\n<main>\n"
          + lib_table($libsByEco[$e] // []; "../") + "\n</main>") } )

  # libraries.csv (UTF-8 s BOM kvůli Excelu, CRLF)
  , { path: "libraries.csv", content: ("\ufeff" + ((
        [["library", "version", "ecosystem", "license", "purl", "sbom_count", "origins", "repo_urls", "sbom_names", "sbom_files"]]
        + [ $libs[] | . as $r | [ $r.sboms[] | $byId[.] | select(. != null) ] as $ss
            | [ $r.name, $r.version, $r.ecosystem, ($r.licenses | map(tostring) | join(", ")), ($r.purls | join(" ")), ($r.sboms | length),
                ($ss | map((.repo | nz) // (.sourceLabel | nz) // .name) | join("; ")), ($ss | map(.repoUrl // "") | join("; ")),
                ($ss | map(.name) | join("; ")), ($ss | map(.file) | join("; ")) ] ]
      ) | map(@csv) | join("\r\n")) + "\r\n") }
) | .path, "\u0000", .content, "\u0000"

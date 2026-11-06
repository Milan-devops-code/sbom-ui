# SBOM (SPDX + CycloneDX) -> jednotný model. Vstup: soubory přes inputs, --slurpfile ov, --arg now.
def truthy: . != null and . != false and . != "";
def nz: select(truthy);
def str: if . == null then "" elif type == "string" then . else tostring end;
def arr: if type == "array" then . else [] end;
def trim_: sub("^\\s+"; "") | sub("\\s+$"; "");
# unique je O(n log n); filtruje prázdné/falsey. Pořadí se změní (řadí) – u licencí/purl/sbomů nevadí.
def uniq_truthy: [ .[] | select(truthy) ] | unique;

# %XX dekódování (ASCII znaky; vícebajtové UTF-8 sekvence nechá zakódované)
def hexval: ascii_downcase | explode | reduce .[] as $c (0; . * 16 + (if $c >= 97 then $c - 87 else $c - 48 end));
def pdec: if type != "string" then "" else
  [match("%[0-9A-Fa-f]{2}|[^%]+|%"; "g").string]
  | map(if test("^%[0-9A-Fa-f]{2}$") then ((.[1:] | hexval) as $v | if $v < 128 then ([$v] | implode) else . end) else . end)
  | join("") end;

# pkg:type/namespace/name@version?qualifiers#subpath
def parse_purl:
  if type == "string" and startswith("pkg:") then
    ((.[4:] | split("#")[0] // "") | split("?")[0] // "") as $s0
    | (if ($s0 | test("^[^/]*/.*@")) or (($s0 | test("/") | not) and ($s0 | test("@")))
       then ($s0 | capture("^(?<a>.*)@(?<v>[^@]*)$") | [.a, .v]) else [$s0, ""] end) as [$s, $ver]
    | ($s | split("/") | map(select(. != ""))) as $p
    | { type: (($p[0] // "") | ascii_downcase),
        name: (($p[1:] | last // "") | pdec),
        namespace: ($p[1:-1] | map(pdec) | join("/")),
        version: ($ver | pdec) }
  else null end;
def display_name:
  if .namespace == "" then .name elif .type == "maven" then "\(.namespace):\(.name)" else "\(.namespace)/\(.name)" end;

def component($name; $version; $purl; $lic; $sbom):
  ($purl | parse_purl) as $p
  | ($name | str) as $nm
  | (if $p then ($p | display_name) else $nm end) as $n0
  | (if ($p == null) and ($n0 | test("^[a-z]+:"; "i")) and (($n0 | contains("/")) | not)
     then ($n0 | sub("^[a-z]+:"; ""; "i")) else $n0 end) as $n1      # "npm:express" -> "express"
  | { name: (if $n1 != "" then $n1 elif $nm != "" then $nm else "(bez názvu)" end),
      version: (($version | str | nz) // ($p.version | nz) // ""),
      purl: ($purl | str),
      ecosystem: ($p.type // ""),
      licenses: ($lic | map(str) | uniq_truthy),
      sbom: $sbom };

# ---- původ SBOMu (repo / zdroj) ----
def mk($host; $owner; $repo):
  ($repo | sub("\\.git$"; ""; "i")) as $r
  | if $owner == "" or $r == "" then null
    else { repo: "\($owner)/\($r)", repoUrl: "https://\($host)/\($owner)/\($r)", host: $host } end;
def repo_from_string:
  if type != "string" or . == "" then null else
    trim_
    | if test("^pkg:github/[^/@?#]+/[^/@?#]+"; "i") then                     # pkg:github/OWNER/REPO@ref
        capture("^pkg:github/(?<o>[^/@?#]+)/(?<r>[^/@?#]+)"; "i") | mk("github.com"; .o; .r)
      elif test("^com\\.github\\.[^/\\s]+/[^/\\s@]+$"; "i") then              # com.github.OWNER/REPO (GitHub export)
        capture("^com\\.github\\.(?<o>[^/\\s]+)/(?<r>[^/\\s@]+)$"; "i") | mk("github.com"; .o; .r)
      elif test("^(?:ssh://)?git@[^/:]+[:/][^/]+/[^/#?\\s]+"; "i") then       # git@host:OWNER/REPO(.git)
        capture("^(?:ssh://)?git@(?<h>[^/:]+)[:/](?<o>[^/]+)/(?<r>[^/#?\\s]+)"; "i") | mk(.h; .o; .r)
      elif test("^(?:git\\+)?(?:https?|git)://(?:[^@/]+@)?[^/:]+(?::\\d+)?/[^/#?\\s]+/[^/#?\\s]+"; "i") then
        capture("^(?:git\\+)?(?:https?|git)://(?:[^@/]+@)?(?<h>[^/:]+)(?::\\d+)?/(?<o>[^/#?\\s]+)/(?<r>[^/#?\\s]+)"; "i")
        | (.h | ascii_downcase) as $h | (.o | ascii_downcase) as $ol
        | if $h == "spdx.org" or $h == "cyclonedx.org" then null
          elif ($h | test("^(www\\.)?github\\.com$")) and ($ol | IN("orgs", "sponsors", "apps", "marketplace")) then null
          else mk($h | sub("^www\\."; ""); .o; .r) end
      else null end
  end;
# první nalezené repo z kandidátů; preferuje github hosty, pak cokoliv "git-like"
def first_repo:
  [.[] | repo_from_string | select(. != null)] as $f
  | first($f[] | select(.host | test("(^|\\.)github\\.com$|\\.ghe\\.com$"))) // first($f[] | select(.host | test("git"))) // null;

def purls: (.externalRefs | arr) | map(select(((.referenceType // "") | str | ascii_downcase) == "purl") | .referenceLocator | str);

def parse_spdx($id):
  . as $d
  | ($d.packages | arr) as $pkgs
  | (($d.documentDescribes | arr)
     + [ $d.relationships | arr | .[]
         | if .relationshipType == "DESCRIBES" and .spdxElementId == $d.SPDXID then .relatedSpdxElement
           elif .relationshipType == "DESCRIBED_BY" and .relatedSpdxElement == $d.SPDXID then .spdxElementId
           else empty end ]) as $root
  | ((first($pkgs[] | select(.SPDXID as $s | $root | any(.[]; . == $s)))) // null) as $rp
  | [ $pkgs[] | select(.SPDXID as $s | $root | any(.[]; . == $s) | not)
      | ((purls | .[0]) // "") as $purl
      # Zachovej licenseConcluded i licenseDeclared (dedup), stejně jako CycloneDX bere všechny licence.
      | [ .licenseConcluded, .licenseDeclared
          | select(type == "string" and (trim_ | IN("", "NOASSERTION", "NONE") | not)) ] as $lic
      | component(.name; .versionInfo; $purl; $lic; $id) ] as $comps
  | ((($rp.name | nz) // ($d.name | nz) // "") | str) as $name
  | ([ (($rp // {}) | purls[]), $rp.name, $d.name, $rp.downloadLocation, $rp.homepage,
       # starší GitHub exporty: https://github.com/OWNER/REPO/dependency_graph/sbom-xxxx
       (if ($d.documentNamespace | type) == "string" and ($d.documentNamespace | test("/dependency_graph/")) then $d.documentNamespace else null end)
     ] | first_repo) as $origin
  | [ ($d.creationInfo.creators | arr | .[]) | select(type == "string" and test("^Tool:"; "i")) | sub("^Tool:\\s*"; ""; "i") ] as $tools
  | (($name | sub("^com\\.github\\."; ""; "i"))
     + (if ($rp.versionInfo | truthy) and $rp.versionInfo != "NOASSERTION" then "@\($rp.versionInfo)" else "" end)) as $label
  | { name: $name, created: ($d.creationInfo.created | str), comps: $comps, origin: $origin, tools: $tools, label: $label, serial: "" };

def cdx_lic: [ arr | .[] | if (.expression | truthy) then .expression elif .license then (.license.id // .license.name) else empty end ];

def parse_cdx($id):
  . as $d
  | $d.metadata.component as $m
  | ($m["bom-ref"]) as $rr
  | def cwalk: arr | .[]
      | ( (if ($rr | truthy) then .["bom-ref"] == $rr else ($m != null and .name == $m.name and .version == $m.version) end) as $isroot
          | if $isroot then empty
            else component(if (.group | truthy) and ((.purl | truthy) | not) then "\(.group)/\(.name)" else .name end;
                           .version; .purl; (.licenses | cdx_lic); $id) end ),
        (.components | cwalk);
    [ $d.components | cwalk ] as $comps
  | (if $m then ([$m.group, $m.name] | map(select(truthy) | str) | join("/")) + (if ($m.version | truthy) then "@\($m.version)" else "" end) else "" end) as $name
  | ($m.externalReferences | arr) as $refs
  | def bytype($t): [ $refs[] | select(.type == $t) | .url ];
    ($d.metadata.properties | arr) as $props
  | [ $props[] | select((.name | str) | test("repo|vcs|scm|source|git"; "i")) | .value ] as $pv
  | (first($props[] | select((.name | str) | test("^(github:repository|github\\.repository|repository)$"; "i")) | .value) // null) as $gh
  | (bytype("vcs")
     + [ $m.purl, (if ($gh | type) == "string" and ($gh | test("^[^/\\s]+/[^/\\s]+$")) then "https://github.com/\($gh)" else null end) ]
     + $pv + bytype("website") + bytype("distribution") | first_repo) as $origin
  | $d.metadata.tools as $t
  | (if ($t | type) == "array" then $t else (($t.components | arr) + ($t.services | arr)) end) as $tl
  | [ $tl[] | [ ((.vendor | nz) // (.group | nz) // (.publisher | nz) // null), .name, .version ]
      | map(select(truthy) | str) | join(" ") | select(. != "") ] as $tools
  | { name: $name, created: ($d.metadata.timestamp | str), comps: $comps, origin: $origin, tools: $tools, label: $name, serial: ($d.serialNumber | str) };

def detect:
  (if (.sbom | type) == "object" then .sbom else . end) as $r       # GitHub export má obal {"sbom": {...}}
  | if ($r.spdxVersion | truthy) or ($r.SPDXID | truthy) then ["SPDX", $r]
    elif $r.bomFormat == "CycloneDX" or (($r.specVersion | truthy) and ($r.components | truthy)) then ["CycloneDX", $r]
    else [null, $r] end;

def resolve_origin($rel; $ovr):
  ((.origin.repo // "") | str) as $repo0 | ((.origin.repoUrl // "") | str) as $url0
  | (if .origin then "sbom" elif (.label | truthy) then "sbom-name" else "file" end) as $src0
  | (if $ovr then
       ((if ($ovr.repo | truthy) then (($ovr.repo | str | repo_from_string) // ("https://github.com/\($ovr.repo)" | repo_from_string)) else null end) as $o
        | (if $o then [$o.repo, $o.repoUrl] else [$repo0, $url0] end)
        | if ($ovr.url | truthy)
          then [ (if .[0] == "" then ((($ovr.url | str | repo_from_string) // {}).repo // "") else .[0] end), ($ovr.url | str) ]
          else . end
        | . + ["sbom-sources.json"])
     else [$repo0, $url0, $src0] end) as [$repo, $url, $src]
  | ($rel | split("/") | last) as $base
  | { repo: $repo, repoUrl: $url, originSource: $src,
      sourceLabel: (($ovr.label | nz | str) // ($repo | nz) // (.label | nz) // ($base | sub("\\.json$"; ""; "i"))) };

def dd($seen): if (. as $c | any($seen[]; . == $c)) then (. + "_" | dd($seen)) else . end;

# ---- hlavní část: vstupy = soubory předané na příkazové řádce ----
# Klíče v override: basename, cesta od kořene (resources/spdx/x.json) i bez prefixu resources/
(($ov[0] // {}) | if type == "object" then
    [ to_entries[] | select((.key | startswith("_") | not) and (.value | type) == "object")
      | .key |= sub("^/+"; "") ]
    | from_entries
  else {} end) as $ovs
| reduce (inputs | {file: input_filename, raw: .}) as $in
    ({ sboms: [], components: [], seen: [],
       log: (if ($ovs | length) > 0 then ["✓ resources/sbom-sources.json: \($ovs | length) záznamů"] else [] end) };
    ($in.file | sub("^(\\./)+"; "")) as $rel
    | (if ($rel | test("(^|/)spdx(/|$)"; "i")) then "SPDX"
       elif ($rel | test("(^|/)cyclonedx(/|$)"; "i")) then "CycloneDX"
       else "CycloneDX" end) as $hint
    | (try ($in.raw | detect) catch [null, null]) as [$fmt, $doc]
    | if $fmt == null then .log += ["! Přeskakuji \($rel): neznámý formát SBOM"]
      else
        . as $st
        | (($rel | sub("^resources/"; "") | sub("\\.json$"; ""; "i")) | dd($st.seen)) as $id
        | (try (if $fmt == "SPDX" then ($doc | parse_spdx($id)) else ($doc | parse_cdx($id)) end) catch {err: (. | tostring)}) as $r
        | if $r.err then .log += ["! Přeskakuji \($rel): chyba při zpracování (\($r.err))"]
          else
            ($rel | split("/") | last) as $base
            | ($rel | sub("^resources/"; "")) as $rel_short
            | ($r | resolve_origin($rel; ($ovs[$rel] // $ovs[$rel_short] // $ovs[$base]))) as $o
            | .seen += [$id]
            | .sboms += [{ id: $id, file: $rel, format: $fmt,
                           name: (($r.name | nz) // ($base | sub("\\.json$"; ""; "i"))),
                           created: $r.created, componentCount: ($r.comps | length),
                           repo: $o.repo, repoUrl: $o.repoUrl, sourceLabel: $o.sourceLabel, originSource: $o.originSource,
                           tool: ($r.tools | map(str) | join(", ")), serialNumber: $r.serial }]
            | .components += $r.comps
            | .log += ((if $fmt != $hint then ["! \($rel): formát \($fmt) je ve složce pro \($hint)"] else [] end)
                       + ["✓ \($rel) (\($fmt)): \($r.comps | length) komponent, původ: \(($o.repo | nz) // $o.sourceLabel) [\($o.originSource)]"])
          end
      end)
| { generatedAt: $now, sboms, components, log }

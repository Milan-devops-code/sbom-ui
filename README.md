# sbom-ui – vyhledávač knihoven v SBOMech

Statická webová stránka (GitHub Pages), ve které se dá hledat, jaké knihovny (a v jakých verzích a licencích)
jsou použité v SBOMech uložených v tomto repu. Podporuje **SPDX** i **CycloneDX** ve formátu JSON.

- bez backendu, bez externích CDN a bez npm závislostí (nic se nenačítá z internetu),
- index všech SBOMů (`docs/index.json`) sestaví GitHub Actions při každém pushi,
- hledání probíhá přímo v prohlížeči.

## Struktura repa

| Cesta | Účel |
|---|---|
| `docs/SBOM-spdx-reports/` | SPDX SBOMy (`*.json`) – např. export z GitHubu (Insights → Dependency graph → Export SBOM) |
| `docs/SBOM-cyclonedx-reports/` | CycloneDX SBOMy (`*.json`, verze 1.4–1.6) |
| `docs/index.html`, `docs/app.js`, `docs/style.css` | samotné UI |
| `docs/index.json` | vygenerovaný index (sestavuje ho skript, ručně neupravovat) |
| `docs/.nojekyll` | vypne Jekyll zpracování (pro lokální/branch publikaci) |
| `scripts/build-index.mjs` | Node skript: projde všechny SBOMy a zapíše `docs/index.json` |
| `.github/workflows/build-sbom-index.yml` | workflow: sestaví index a nasadí Pages |

## Funkce UI

- hledání podle názvu knihovny, verze, purl, licence nebo ekosystému (více slov = všechna musí sedět),
- filtry: formát (SPDX / CycloneDX), konkrétní SBOM, ekosystém (npm, maven, pypi …),
- **seskupení**: stejná knihovna + verze ve více SBOMech je jeden řádek se seznamem zdrojů a počtem SBOMů,
- řazení kliknutím na hlavičku sloupce,
- statistiky (počet SBOMů, unikátních knihoven…),
- odkaz na konkrétní hledání: např. `…/sbom-ui/?q=lodash` (sdílí se i filtry),
- export aktuálních výsledků do CSV (UTF-8, otevře se v Excelu),
- kořenový balíček (samotné repo/aplikace) se do výsledků nezapočítává
  (SPDX: `documentDescribes` / vztah `DESCRIBES`; CycloneDX: `metadata.component`).

## Nastavení GitHub Pages

1. Nahraj obsah této složky do kořene repa `Milan-devops-code/sbom-ui` (branch `main`).
2. **Settings → Pages → Build and deployment → Source: _GitHub Actions_.**
3. Spusť workflow (Actions → *Build SBOM index & deploy Pages* → *Run workflow*) nebo pushni změnu v `docs/`.
4. Stránka poběží na `https://milan-devops-code.github.io/sbom-ui/`
   (na Enterprise Cloud s privátní viditelností dostane jinou, náhodnou adresu `*.pages.github.io`; všechny cesty v UI jsou relativní, takže funguje obojí).

### ⚠️ Viditelnost – Free vs. Enterprise Cloud

- **GitHub Free (organizace): Pages fungují jen pro _veřejná_ repa.** U privátního repa na Free plánu Pages vůbec nezapneš.
  Pro test proto použij **lokální náhled** (níže). Repo dočasně zveřejnit nedoporučuji – SBOMy prozrazují, jaké knihovny a verze používáte.
- Na plánu **Team** jdou Pages z privátního repa, ale **stránka je veřejně dostupná komukoliv na internetu**.
- **GitHub Enterprise Cloud:** lze publikovat privátně – jen pro uživatele s přístupem k repu.
  Postup: v nastavení organizace (*Settings → Pages* / politika členů) povol privátní publikování, pak v repu
  *Settings → Pages → Visibility* zvol **Private**. Zkontroluj to dřív, než do repa nahraješ ostré SBOMy.

Stránka má `noindex`, ale to není ochrana – o přístupu rozhoduje jen viditelnost Pages.

## Přidání SBOMu

1. Ulož JSON do správné složky:
   - SPDX → `docs/SBOM-spdx-reports/nazev-aplikace.json`
   - CycloneDX → `docs/SBOM-cyclonedx-reports/nazev-aplikace.json`
   (podsložky jsou povolené; název souboru se použije, když SBOM nemá vlastní název aplikace)
2. Commit + push do `main` → workflow index přegeneruje a nasadí. Nic dalšího není potřeba.
3. Ukázkové soubory `sample-*.json` klidně smaž, až nahraješ vlastní.

Skript rozpozná formát podle obsahu (GitHub export s obalem `{"sbom": {...}}` i čisté SPDX 2.x, CycloneDX podle `bomFormat`),
neplatné nebo neznámé soubory jen přeskočí s varováním v logu workflow.

## Lokální náhled

Potřebuješ Node.js 18+ (v Actions se používá Node 22).

```bash
node scripts/build-index.mjs
npx serve docs            # nebo: python3 -m http.server 8000 -d docs
```

Pak otevři vypsanou adresu (např. http://localhost:3000 nebo http://localhost:8000).
Otevření `docs/index.html` přímo jako souboru (`file://`) nefunguje – prohlížeč nedovolí načíst `index.json`.

Vygenerovaný `docs/index.json` je v repu commitnutý kvůli lokálnímu náhledu. Při nasazení ho workflow
vždy vytvoří znovu, takže nevadí, když bude v repu starší.

## Omezení

- Jen **JSON** formáty. SPDX tag-value (`.spdx`), RDF a CycloneDX XML se zatím nezpracují.
- Zranitelnosti (CVE) se nezobrazují – jde o inventář knihoven, ne o security scanner.
- Seskupuje se podle ekosystému + názvu + verze; stejná knihovna zapsaná v různých SBOMech jinak (bez purl, jiný název) se nespojí.
- Licence: u SPDX se bere `licenseConcluded`, jinak `licenseDeclared` (`NOASSERTION` = neuvedeno). GitHub export licence často neobsahuje.
- U verzí z GitHub Actions (např. `4.*.*`) jde o rozsah z workflow, ne o přesnou verzi.
- Vše se načítá do prohlížeče: pohodlně pro stovky SBOMů / desítky tisíc komponent; v tabulce se zobrazí max. 2000 řádků (CSV export obsahuje vše).

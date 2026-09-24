package sh.mlab.vulnscan

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

// Ported from the VS Code extension's test suite, so both clients are held to
// the same behaviour.

private fun json(s: String): JsonObject = JsonParser.parseString(s).asJsonObject
private fun fixture(name: String) = File(System.getProperty("mlab.fixtures", "src/test/fixtures"), name).readText()

class LockfilesTest {
    @Test fun `every supported basename is recognised, case insensitively, on any separator`() {
        for (n in SUPPORTED_BASENAMES) {
            assertTrue(isSupportedLockfile("/a/b/$n"))
            assertTrue(isSupportedLockfile("C:\\x\\${n.uppercase()}"))
        }
        assertFalse(isSupportedLockfile("/a/not-a-lockfile.txt"))
        assertFalse(isSupportedLockfile("/a/Cargo.toml"))
    }

    @Test fun `formats follow the server parsers`() {
        assertEquals("cargo", detectFormat("Cargo.lock"))
        assertEquals("npm", detectFormat("npm-shrinkwrap.json"))
        assertEquals("pip", detectFormat("x/requirements.txt"))
        assertNull(detectFormat("README.md"))
    }
}

class CvssTest {
    @Test fun `roundUp follows the v31 spec`() {
        assertEquals(4.0, roundUp(4.0), 0.0)
        assertEquals(6.2, roundUp(6.2), 0.0)
        assertEquals(6.2, roundUp(6.11), 0.0)
        assertEquals(4.1, roundUp(4.00001), 0.0)
        assertEquals(4.0, roundUp(4.0000001), 0.0)
    }

    @Test fun `scores reference vectors`() {
        assertEquals(6.2, baseScoreV3("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")!!, 0.0)
        assertEquals(10.0, baseScoreV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")!!, 0.0)
        assertEquals(9.8, baseScoreV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")!!, 0.0)
        assertEquals(0.0, baseScoreV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")!!, 0.0)
        assertEquals(baseScoreV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), baseScoreV3("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
    }

    @Test fun `refuses what it cannot score`() {
        assertNull(baseScoreV3("AV:N/AC:L/Au:N/C:P/I:P/A:P"))
        assertNull(baseScoreV3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"))
        assertNull(baseScoreV3("CVSS:3.1/AV:N/AC:L"))
        assertNull(scoreOf(""))
        assertNull(scoreOf("AV:N/AC:L/Au:N/C:P/I:P/A:P"))
        assertEquals(9.8, scoreOf("  9.8  ")!!, 0.0)
    }
}

class ScanApiTest {
    private val duplicated = json(
        """{"hash":"abc123","count":2,"truncated":false,
        "packages":[{"name":"time","version":"0.1.43"},{"name":"serde","version":"1.0.100"}],
        "results":[{"ok":true,"vulns":[
          {"id":"GHSA-wcg3-cvx6-7396","aliases":["CVE-2020-26235","RUSTSEC-2020-0071"],"summary":"Segmentation fault in time",
           "severity":[{"score":"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]},
          {"id":"RUSTSEC-2020-0071","aliases":["CVE-2020-26235"],"summary":"Potential segfault",
           "database_specific":{"severity":"HIGH"},"affected":[{"ranges":[{"events":[{"fixed":"0.2.23"}]}]}]}]},
          {"ok":true,"vulns":[]}]}""",
    )

    @Test fun `severity model`() {
        assertEquals(Severity.LOW, severityOf(json("""{"database_specific":{"severity":"LOW"},"severity":[{"score":"9.8"}]}""")))
        assertEquals(Severity.MEDIUM, severityOf(json("""{"database_specific":{"severity":"MODERATE"}}""")))
        assertEquals(Severity.UNKNOWN, severityOf(json("""{"database_specific":{"severity":"SPICY"}}""")))
        assertEquals(Severity.MEDIUM, severityOf(json("""{"severity":[{"score":"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}""")))
        assertEquals(Severity.CRITICAL, severityOf(json("""{"severity":[{"score":"AV:N/AC:L/Au:N/C:P/I:P/A:P"},{"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}""")))
        assertEquals(Severity.UNKNOWN, severityOf(json("{}")))
        val at = { s: String -> severityOf(json("""{"severity":[{"score":"$s"}]}""")) }
        assertEquals(Severity.CRITICAL, at("9"))
        assertEquals(Severity.HIGH, at("8.9"))
        assertEquals(Severity.MEDIUM, at("4"))
        assertEquals(Severity.LOW, at("0.1"))
        assertEquals(Severity.UNKNOWN, at("0"))
    }

    @Test fun `cve and fix resolution`() {
        assertEquals("CVE-2020-26235", cveOf(json("""{"id":"GHSA-x","aliases":["RUSTSEC-1","CVE-2020-26235"]}""")))
        assertEquals("GHSA-x", cveOf(json("""{"id":"GHSA-x","aliases":["RUSTSEC-1"]}""")))
        assertEquals("UNKNOWN", cveOf(json("{}")))
        assertEquals("2.3.1", fixedVersionOf(json("""{"affected":[{"ranges":[{"events":[{"fixed":"1.0.0"}]}]},{"ranges":[{"events":[{"fixed":"2.3.1"}]}]}]}""")))
        assertNull(fixedVersionOf(json("""{"affected":[{"ranges":[{"events":[{"introduced":"0"}]}]}]}""")))
    }

    @Test fun `the same CVE from two advisories collapses, keeping the worst and backfilling the fix`() {
        val out = buildOutcome(duplicated)
        assertEquals(1, out.findings.size)
        val f = out.findings[0]
        assertEquals("CVE-2020-26235", f.cve)
        assertEquals(Severity.HIGH, f.severity)
        assertEquals("0.2.23", f.fixedVersion)
        assertEquals("https://vuln.mlab.sh/cve/CVE-2020-26235", f.url)
        assertEquals("1 high across 1 package", summarize(out))
    }

    @Test fun `unresolved packages are never counted as clean`() {
        val out = buildOutcome(json("""{"hash":"h","count":2,"truncated":false,
            "packages":[{"name":"ok-pkg","version":"1.0"},{"name":"mystery","version":"2.0"}],
            "results":[{"ok":true,"vulns":[]},{"ok":false}]}"""))
        assertEquals(listOf("mystery@2.0"), out.unresolved)
        assertEquals("No known vulnerabilities found", summarize(out))
    }

    @Test fun `a GHSA only advisory has no CVE link`() {
        val out = buildOutcome(json("""{"hash":"h","count":1,"truncated":false,"packages":[{"name":"x","version":"1.0"}],"results":[{"ok":true,"vulns":[{"id":"GHSA-zzzz"}]}]}"""))
        assertNull(out.findings[0].url)
    }
}

class IocTest {
    @Test fun `cleans accidental punctuation only`() {
        assertEquals("8.8.8.8", cleanIndicator("  8.8.8.8  "))
        assertEquals("example.com", cleanIndicator("\"example.com\""))
        assertEquals("security@example.com", cleanIndicator("<security@example.com>"))
        assertEquals("1.1.1.1", cleanIndicator("(1.1.1.1);"))
        assertEquals("https://example.com/a/", cleanIndicator("https://example.com/a/"))
    }

    @Test fun `detects each kind, with collisions resolved`() {
        val cases = mapOf(
            "https://example.com/a?b=c" to IndicatorKind.URL,
            "http://admin:x@192.168.9.7:8080/a.exe" to IndicatorKind.URL,
            "security@example.com" to IndicatorKind.EMAIL,
            "00:1A:2B:3C:4D:5E" to IndicatorKind.MAC,
            "00-1A-2B-3C-4D-5E" to IndicatorKind.MAC,
            "001a.2b3c.4d5e" to IndicatorKind.MAC,
            "001A2B3C4D5E" to IndicatorKind.MAC,
            "d41d8cd98f00b204e9800998ecf8427e" to IndicatorKind.HASH,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" to IndicatorKind.HASH,
            "8.8.8.8" to IndicatorKind.IP,
            "2606:4700:4700::1111" to IndicatorKind.IP,
            "vuln.mlab.sh" to IndicatorKind.DOMAIN,
        )
        cases.forEach { (v, k) -> assertEquals(v, k, detectKind(v)) }
        for (v in listOf("999.1.1.1", "1.2.3", "256.0.0.1", "", "hello world", "CVE-2021-44228", "/usr/bin/env")) {
            assertEquals(v, IndicatorKind.UNKNOWN, detectKind(v))
        }
    }

    @Test fun `routing, web pages and quota`() {
        for (k in IndicatorKind.entries.filter { it.isSupported }) {
            assertNotEquals(k.name, endpointFor("https://mlab.sh/api/v1", k, "x") != null, k.isActive)
            assertNotNull(webUrlFor("https://mlab.sh", k, "v"))
        }
        assertEquals("https://mlab.sh/api/v1/scan/ip?ip=1.1.1.1", endpointFor("https://mlab.sh/api/v1/", IndicatorKind.IP, "1.1.1.1"))
        assertEquals("https://mlab.sh/url?q=https%3A%2F%2Fexample.com%2Fa%20b", webUrlFor("https://mlab.sh", IndicatorKind.URL, "https://example.com/a b"))
        assertEquals("https://mlab.sh/email/a%2Bb%40example.com", webUrlFor("https://mlab.sh", IndicatorKind.EMAIL, "a+b@example.com"))
        assertEquals("https://mlab.sh/ip/%3A%3A1", webUrlFor("https://mlab.sh/", IndicatorKind.IP, "::1"))
        assertNull(webUrlFor("https://mlab.sh", IndicatorKind.UNKNOWN, "x"))
        assertEquals(setOf(IndicatorKind.IP, IndicatorKind.DOMAIN), IndicatorKind.entries.filter { it.costsQuota }.toSet())
    }

    @Test fun `domain polling is bounded`() {
        assertEquals(DomainState.PENDING, readState(json("""{"status":"pending"}""")))
        assertEquals(DomainState.DONE, readState(json("{}")))
        assertTrue(pollDelay(1) > pollDelay(0))
        assertTrue((0 until MAX_POLLS).sumOf { pollDelay(it) } <= 5 * 60 * 1000)
    }

    @Test fun `responses normalise per kind`() {
        val url = summarizeIndicator(IndicatorKind.URL, "u", json("""{"scheme":"http","host":"192.168.9.7","has_userinfo":true,"port":null,
            "findings":[{"severity":"high","title":"Credentials"},{"severity":"medium","title":"HTTP"}]}"""))
        assertEquals("high", worstIndicatorSeverity(url.findings))
        assertTrue(url.facts.any { it.label == "Credentials in URL" })
        assertFalse(url.facts.any { it.label == "Port" })
        assertEquals(Tone.GOOD, summarizeIndicator(IndicatorKind.HASH, "x", json("""{"verdict":"known_good"}""")).verdict?.tone)
        assertEquals(Tone.NEUTRAL, summarizeIndicator(IndicatorKind.HASH, "x", json("""{"found":false}""")).verdict?.tone)
        assertEquals(Tone.WARN, summarizeIndicator(IndicatorKind.EMAIL, "x", json("""{"score":{"band":"suspect"}}""")).verdict?.tone)
        val ip = summarizeIndicator(IndicatorKind.IP, "8.8.8.8", json("""{"city":"Ashburn","region":"Virginia","country":"United States","hosting":true}"""))
        assertEquals(Tone.NEUTRAL, ip.verdict?.tone)
        assertTrue(ip.facts.any { it.label == "Location" && it.value == "Ashburn, Virginia, United States" })
        assertEquals(Tone.WARN, summarizeIndicator(IndicatorKind.IP, "x", json("""{"proxy":true}""")).verdict?.tone)
        assertTrue(isCompleted(json("""{"status":"completed","results":{}}""")))
        assertFalse(isCompleted(json("""{"status":"completed","results":null}""")))
    }
}

class IntelTest {
    @Test fun `parses records defensively and matches ids exactly`() {
        val i = parseRecord(json("""{"id":"CVE-2021-44228","cvss_score":10,"cvss_severity":"CRITICAL","epss_score":0.99999,"in_kev":true,
            "kev_due_date":"2021-12-24","weaknesses":["CWE-20","CWE-502"]}"""))!!
        assertEquals("critical", i.cvssSeverity)
        assertTrue(i.inKev)
        assertEquals(listOf("CWE-20", "CWE-502"), i.weaknesses)
        val n = parseRecord(json("""{"id":"CVE-1","cvss_score":null,"weaknesses":null,"in_kev":"yes"}"""))!!
        assertNull(n.cvssScore)
        assertFalse(n.inKev)
        assertTrue(n.weaknesses.isEmpty())
        assertNull(parseRecord(json("""{"cvss_score":9}""")))
        val records = JsonParser.parseString("""[{"id":"CVE-2021-45046"},{"id":"CVE-2021-44228","cvss_score":10}]""").asJsonArray
        assertEquals(10.0, pickExact("cve-2021-44228", records)!!.cvssScore!!, 0.0)
        assertNull(pickExact("CVE-2021-4422", records))
    }

    @Test fun `epss labels and urgency`() {
        fun w(e: Double?, kev: Boolean = false) = CveIntel("CVE-1", epssScore = e, inKev = kev)
        assertEquals("100%", epssLabel(w(0.99999)))
        assertEquals("1.6%", epssLabel(w(0.01641)))
        assertEquals("0.02%", epssLabel(w(0.0002)))
        assertEquals("<0.01%", epssLabel(w(0.00001)))
        assertNull(epssLabel(w(null)))
        assertEquals(Urgency.EXPLOITED, urgencyOf(w(0.00001, true)))
        assertEquals(Urgency.LIKELY, urgencyOf(w(0.1)))
        assertEquals(Urgency.NORMAL, urgencyOf(w(0.099)))
        assertEquals("https://vuln.mlab.sh/api/v1/cve?q=CVE-2021-44228&limit=5", intelUrl("https://vuln.mlab.sh", "CVE-2021-44228"))
    }
}

class DiagnosticsTest {
    @Test fun `severity floor mapping`() {
        assertEquals(DiagLevel.ERROR, levelFor(Severity.HIGH, "any"))
        assertEquals(DiagLevel.WARNING, levelFor(Severity.MEDIUM, "any"))
        assertEquals(DiagLevel.INFORMATION, levelFor(Severity.LOW, "any"))
        assertEquals(DiagLevel.INFORMATION, levelFor(Severity.MEDIUM, "high"))
        assertEquals(DiagLevel.ERROR, levelFor(Severity.HIGH, "high"))
        assertEquals(DiagLevel.WARNING, levelFor(Severity.MEDIUM, "nonsense"))
        FLOORS.forEach { assertTrue(it in FLOOR_RANK) }
    }

    @Test fun `locates declarations, not comments or substrings`() {
        val cargo = fixture("Cargo.lock")
        val hit = locateLine(cargo, "time", "0.1.43")
        val line = cargo.lines()[hit.line]
        assertEquals("name = \"time\"", line.trim())
        assertEquals("time", line.substring(hit.col, hit.endCol))

        val npm = fixture("package-lock.json")
        val l = npm.lines()[locateLine(npm, "lodash", "4.17.11").line]
        assertTrue(l, "lodash" in l && "4.17.11" in l)

        assertEquals(1, locateLine("name = \"serde_json\"\nname = \"serde\"", "serde", "").line)
        assertEquals(3, locateLine("dependencies = [\"time\"]\n\n[[package]]\nname = \"time\"\nversion = \"0.1.43\"", "time", "0.1.43").line)
        assertEquals(1, locateLine("first\r\nname = \"left-pad\"\r\n", "left-pad", "").line)
        assertEquals(Hit(0, 0, 0), locateLine("", "anything", "1.0"))
        assertEquals(0, locateLine("dep = \"foo.bar\" 1.0", "foo.bar", "1.0").line)
        locateLine("a\nb", "foo.bar+baz(", "1.0")
    }
}

class CacheTest {
    private val outcome = ScanOutcome(
        listOf(Finding("a@1", "a", "1", "CVE-1", Severity.MEDIUM), Finding("b@1", "b", "1", "CVE-2", Severity.CRITICAL)),
        emptyList(), 2, false, "h",
    )

    @Test fun `hits need the same content and freshness`() {
        val c = ScanCache(null)
        val now = 1_000_000_000_000L
        c.put("/p/Cargo.lock", "Cargo.lock", "h1", outcome, now)
        assertNotNull(c.lookup("/p/Cargo.lock", "h1", now))
        assertNull(c.lookup("/p/Cargo.lock", "h2", now))
        assertNull(c.lookup("/p/Cargo.lock", "h1", now + SCAN_MAX_AGE_MS + 1))
        assertNotNull(c.peek("/p/Cargo.lock"))
        assertEquals(Severity.CRITICAL, c.peek("/p/Cargo.lock")!!.worstSeverity)
    }

    @Test fun `entries past retention are dropped on write`() {
        val c = ScanCache(null)
        val now = 1_000_000_000_000L
        c.put("/old", "x", "h", outcome, now - RETENTION_MS - 1)
        c.put("/new", "x", "h", outcome, now)
        assertEquals(listOf("/new"), c.paths())
    }

    @Test fun `survives a round trip through its file`() {
        val f = File.createTempFile("mlab", ".json").toPath()
        ScanCache(f).put("/p/go.sum", "go.sum", "h", outcome)
        val back = ScanCache(f).peek("/p/go.sum")!!
        assertEquals(2, back.outcome.findings.size)
        assertEquals(Severity.MEDIUM, back.outcome.findings[0].severity)
    }

    @Test fun `intel cache partitions and expires`() {
        val c = IntelCache(null)
        val now = 1_000_000_000_000L
        c.putAll(mapOf("CVE-A" to CveIntel("CVE-A")), now)
        val (known, missing) = c.partition(listOf("CVE-A", "CVE-B", "CVE-B"), now)
        assertEquals(setOf("CVE-A"), known.keys)
        assertEquals(listOf("CVE-B"), missing)
        assertNull(c.get("CVE-A", now + INTEL_MAX_AGE_MS + 1))
    }

    @Test fun `sha256 is hex`() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sha256Hex(ByteArray(0)))
    }
}

class ReportHtmlTest {
    @Test fun `report escapes untrusted text and emits no script`() {
        val o = ScanOutcome(listOf(Finding("<x>@1", "<x>", "1", "CVE-1", Severity.HIGH, summary = "<img src=x onerror=alert(1)>")), emptyList(), 1, false, "h")
        val html = reportHtml("Cargo.lock", o, RenderOpts(dark = false, embedAssets = false))
        assertFalse("<script" in html)
        assertFalse("<img src=x" in html)
        assertTrue("&lt;img src=x" in html)
    }
}

<?php
/**
 * LiteSpeed Cache — CVE-2024-28000 Vulnerability Checker
 * -----------------------------------------------------------------------------
 * Standalone, non-destructive checker for the critical unauthenticated
 * privilege-escalation flaw in the LiteSpeed Cache WordPress plugin
 * (CVE-2024-28000, CVSS 9.8).
 *
 *   Vulnerable : LiteSpeed Cache  1.9  –  6.3.0.1
 *   Patched    : LiteSpeed Cache  6.4  and later
 *
 * This tool only FINGERPRINTS the installed plugin version and reports whether
 * that version falls in the vulnerable range. It does NOT exploit the
 * vulnerability, brute-force any hash, simulate roles, or create accounts.
 * Version detection is the reliable way to confirm exposure and to verify a
 * patch, and it is safe to run repeatedly.
 *
 * ---------------------------------------------------------------------------
 *  AUTHORIZED USE ONLY. Run this only against servers you own or have explicit
 *  written permission to test. Checking systems you do not control may be
 *  illegal in your jurisdiction.
 * ---------------------------------------------------------------------------
 *
 * Usage:
 *   - Web:  place on a PHP-enabled server, open in a browser, enter target URL.
 *   - CLI:  php litespeed-cache-vuln-check.php https://my-test-server.example
 */

declare(strict_types=1);

const FIRST_VULNERABLE = '1.9';
const FIRST_PATCHED    = '6.4';
const HTTP_TIMEOUT     = 15;
const USER_AGENT       = 'LSCache-CVE-2024-28000-VersionChecker/1.0 (+authorized-testing)';

/**
 * Perform a simple GET request. Returns [httpCode, body] or [0, ''] on failure.
 *
 * @return array{0:int,1:string}
 */
function http_get(string $url): array
{
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_TIMEOUT        => HTTP_TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => HTTP_TIMEOUT,
            CURLOPT_USERAGENT      => USER_AGENT,
            // We are only reading public files; keep TLS verification ON.
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return [$code, is_string($body) ? $body : ''];
    }

    // Fallback to streams.
    $context = stream_context_create([
        'http' => ['method' => 'GET', 'timeout' => HTTP_TIMEOUT, 'user_agent' => USER_AGENT, 'follow_location' => 1],
        'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
    ]);
    $body = @file_get_contents($url, false, $context);
    $code = 0;
    if (isset($http_response_header[0]) && preg_match('#\s(\d{3})\s#', $http_response_header[0], $m)) {
        $code = (int) $m[1];
    }
    return [$body === false ? 0 : $code, $body === false ? '' : $body];
}

/** Normalise a user-supplied base URL. */
function normalize_base(string $raw): ?string
{
    $raw = trim($raw);
    if ($raw === '') {
        return null;
    }
    if (!preg_match('#^https?://#i', $raw)) {
        $raw = 'https://' . $raw;
    }
    $parts = parse_url($raw);
    if (!$parts || empty($parts['host'])) {
        return null;
    }
    $scheme = $parts['scheme'] ?? 'https';
    $host   = $parts['host'];
    $port   = isset($parts['port']) ? ':' . $parts['port'] : '';
    $path   = rtrim($parts['path'] ?? '', '/');
    return sprintf('%s://%s%s%s', $scheme, $host, $port, $path);
}

/**
 * Attempt to detect the installed LiteSpeed Cache version using several
 * public, non-intrusive fingerprints.
 *
 * @return array{version:?string,detected:bool,sources:array<int,string>,notes:array<int,string>}
 */
function detect_version(string $base): array
{
    $version = null;
    $sources = [];
    $notes   = [];

    // 1) Canonical source of truth: the plugin's own readme.txt "Stable tag".
    $readmeUrl = $base . '/wp-content/plugins/litespeed-cache/readme.txt';
    [$code, $body] = http_get($readmeUrl);
    if ($code === 200 && stripos($body, 'litespeed') !== false) {
        if (preg_match('/Stable tag:\s*([0-9][0-9.]*)/i', $body, $m)) {
            $version = $m[1];
            $sources[] = 'readme.txt (Stable tag) → ' . $readmeUrl;
        } else {
            $notes[] = 'readme.txt is reachable but no "Stable tag" line was found.';
        }
    }

    // 2) Asset version query strings (?ver=) on bundled CSS/JS, if readme failed.
    if ($version === null) {
        [$hc, $html] = http_get($base . '/');
        if ($hc === 200 && $html !== '') {
            if (preg_match('#/wp-content/plugins/litespeed-cache/[^"\']*\?ver=([0-9][0-9.]*)#i', $html, $m)) {
                $version = $m[1];
                $sources[] = 'asset ?ver= string on home page';
            } elseif (stripos($html, 'litespeed-cache') !== false || stripos($html, 'X-LiteSpeed-Cache') !== false) {
                $notes[] = 'LiteSpeed Cache appears present on the home page, but no version string was exposed.';
            }
        }
    }

    // 3) Response-header hint (confirms plugin presence, not version).
    if ($version === null) {
        [$hc2, $home] = http_get($base . '/');
        if ($hc2 !== 0 && stripos($home, 'litespeed') !== false) {
            $notes[] = 'A LiteSpeed signature was seen but the exact version could not be read remotely.';
        }
    }

    return [
        'version'  => $version,
        'detected' => $version !== null,
        'sources'  => $sources,
        'notes'    => $notes,
    ];
}

/**
 * Classify a detected version against CVE-2024-28000.
 *
 * @return array{status:string,label:string,detail:string}
 */
function classify(?string $version): array
{
    if ($version === null) {
        return [
            'status' => 'unknown',
            'label'  => 'UNKNOWN',
            'detail' => 'Could not determine the installed LiteSpeed Cache version remotely. '
                      . 'Check the version in wp-admin → Plugins, or on the server at '
                      . 'wp-content/plugins/litespeed-cache/litespeed-cache.php (the "Version:" header).',
        ];
    }

    if (version_compare($version, FIRST_PATCHED, '>=')) {
        return [
            'status' => 'patched',
            'label'  => 'NOT VULNERABLE',
            'detail' => "Version {$version} is at or above the patched release (" . FIRST_PATCHED . "). "
                      . 'This installation is not affected by CVE-2024-28000.',
        ];
    }

    if (version_compare($version, FIRST_VULNERABLE, '>=')) {
        return [
            'status' => 'vulnerable',
            'label'  => 'VULNERABLE',
            'detail' => "Version {$version} is within the affected range (" . FIRST_VULNERABLE . ' – 6.3.0.1). '
                      . 'This installation is vulnerable to CVE-2024-28000. Update to ' . FIRST_PATCHED . ' or later immediately.',
        ];
    }

    return [
        'status' => 'likely_safe',
        'label'  => 'LIKELY NOT VULNERABLE',
        'detail' => "Version {$version} predates the affected range (" . FIRST_VULNERABLE . '). '
                  . 'CVE-2024-28000 was reported for 1.9–6.3.0.1, but upgrading to the latest release is still strongly recommended.',
    ];
}

/** Run a scan and return the full result structure. */
function run_scan(string $rawTarget): array
{
    $base = normalize_base($rawTarget);
    if ($base === null) {
        return ['error' => 'Invalid target URL.'];
    }
    $detection = detect_version($base);
    $verdict   = classify($detection['version']);
    return [
        'target'    => $base,
        'detection' => $detection,
        'verdict'   => $verdict,
    ];
}

/* ---------------------------------------------------------------------------
 *  CLI mode
 * ------------------------------------------------------------------------- */
if (PHP_SAPI === 'cli') {
    $target = $argv[1] ?? '';
    if ($target === '') {
        fwrite(STDERR, "Usage: php " . basename(__FILE__) . " <target-url>\n");
        exit(2);
    }
    $r = run_scan($target);
    if (isset($r['error'])) {
        fwrite(STDERR, "Error: {$r['error']}\n");
        exit(2);
    }
    echo "Target : {$r['target']}\n";
    echo "Version: " . ($r['detection']['version'] ?? 'undetected') . "\n";
    echo "Result : {$r['verdict']['label']}\n";
    echo "Detail : {$r['verdict']['detail']}\n";
    foreach ($r['detection']['sources'] as $s) {
        echo "Source : {$s}\n";
    }
    foreach ($r['detection']['notes'] as $n) {
        echo "Note   : {$n}\n";
    }
    exit($r['verdict']['status'] === 'vulnerable' ? 1 : 0);
}

/* ---------------------------------------------------------------------------
 *  Web mode
 * ------------------------------------------------------------------------- */
$result = null;
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && isset($_POST['target'])) {
    $result = run_scan((string) $_POST['target']);
}

$statusColors = [
    'vulnerable'   => '#b4232a',
    'patched'      => '#1a7f4b',
    'likely_safe'  => '#1a7f4b',
    'unknown'      => '#8a6d00',
    'error'        => '#b4232a',
];
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LiteSpeed Cache — CVE-2024-28000 Checker</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    margin: 0; padding: 24px; line-height: 1.5;
    background: #f6f7f9; color: #1b1f24;
  }
  @media (prefers-color-scheme: dark) {
    body { background: #14171a; color: #e6e9ec; }
    .card { background: #1d2126 !important; border-color: #2c333b !important; }
    input[type=text] { background: #14171a; color: #e6e9ec; border-color: #2c333b; }
    code, pre { background: #14171a !important; }
  }
  .wrap { max-width: 760px; margin: 0 auto; }
  h1 { font-size: 1.4rem; margin: 0 0 4px; }
  .sub { color: #6b7280; margin: 0 0 20px; font-size: .92rem; }
  .card { background: #fff; border: 1px solid #e3e6ea; border-radius: 12px; padding: 20px; margin-bottom: 18px; }
  label { font-weight: 600; display: block; margin-bottom: 6px; }
  input[type=text] { width: 100%; padding: 10px 12px; font-size: 1rem; border: 1px solid #cbd2da; border-radius: 8px; }
  button { margin-top: 12px; padding: 10px 18px; font-size: 1rem; font-weight: 600; border: 0; border-radius: 8px; background: #2563eb; color: #fff; cursor: pointer; }
  button:hover { background: #1d4ed8; }
  .verdict { font-size: 1.15rem; font-weight: 700; padding: 10px 14px; border-radius: 8px; color: #fff; display: inline-block; }
  .kv { margin: 10px 0; }
  .kv b { display: inline-block; min-width: 90px; color: #6b7280; font-weight: 600; }
  code { background: #f0f2f5; padding: 1px 6px; border-radius: 4px; font-size: .9em; }
  ul { margin: 8px 0; padding-left: 20px; }
  .note { font-size: .88rem; color: #6b7280; }
  .warn { background: #fff8e6; border: 1px solid #f0d98a; border-radius: 8px; padding: 12px 14px; font-size: .9rem; margin-bottom: 18px; }
  @media (prefers-color-scheme: dark) { .warn { background: #2a2410; border-color: #4d421a; } }
  footer { font-size: .82rem; color: #8a929c; margin-top: 24px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>LiteSpeed Cache — CVE-2024-28000 Vulnerability Checker</h1>
  <p class="sub">Non-destructive version check. Vulnerable range: <b>1.9 – 6.3.0.1</b> · Patched: <b>6.4+</b></p>

  <div class="warn">
    <b>Authorized use only.</b> Run this against servers you own or have explicit written
    permission to test. This tool only reads the plugin's public version information — it does
    not attempt to exploit the vulnerability.
  </div>

  <div class="card">
    <form method="post">
      <label for="target">Target site URL</label>
      <input type="text" id="target" name="target" placeholder="https://my-test-server.example"
             value="<?= htmlspecialchars((string) ($_POST['target'] ?? ''), ENT_QUOTES) ?>" autofocus>
      <button type="submit">Check version</button>
    </form>
  </div>

<?php if ($result !== null): ?>
  <div class="card">
  <?php if (isset($result['error'])): ?>
    <span class="verdict" style="background: <?= $statusColors['error'] ?>">ERROR</span>
    <p><?= htmlspecialchars($result['error'], ENT_QUOTES) ?></p>
  <?php else:
      $v = $result['verdict'];
      $d = $result['detection'];
      $color = $statusColors[$v['status']] ?? '#6b7280';
  ?>
    <span class="verdict" style="background: <?= $color ?>"><?= htmlspecialchars($v['label'], ENT_QUOTES) ?></span>
    <div class="kv" style="margin-top:14px"><b>Target</b> <code><?= htmlspecialchars($result['target'], ENT_QUOTES) ?></code></div>
    <div class="kv"><b>Version</b> <code><?= htmlspecialchars($d['version'] ?? 'undetected', ENT_QUOTES) ?></code></div>
    <div class="kv"><b>Verdict</b> <?= htmlspecialchars($v['detail'], ENT_QUOTES) ?></div>
    <?php if (!empty($d['sources'])): ?>
      <div class="kv"><b>Sources</b></div>
      <ul><?php foreach ($d['sources'] as $s): ?><li class="note"><?= htmlspecialchars($s, ENT_QUOTES) ?></li><?php endforeach; ?></ul>
    <?php endif; ?>
    <?php if (!empty($d['notes'])): ?>
      <ul><?php foreach ($d['notes'] as $n): ?><li class="note"><?= htmlspecialchars($n, ENT_QUOTES) ?></li><?php endforeach; ?></ul>
    <?php endif; ?>
  <?php endif; ?>
  </div>
<?php endif; ?>

  <footer>
    CVE-2024-28000 — unauthenticated privilege escalation in LiteSpeed Cache (≤ 6.3.0.1), fixed in 6.4.
    Remediation: update the plugin to the latest version. This checker reports exposure by version only.
  </footer>
</div>
</body>
</html>

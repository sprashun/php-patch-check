<?php
// Read-only diagnostics for the localhost PHP Patch Check lab.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function read_setting(string $name): ?string
{
    $value = ini_get($name);
    return $value === false ? null : $value;
}

$isPhp85 = PHP_MAJOR_VERSION === 8 && PHP_MINOR_VERSION === 5;

$report = [
    'php_version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'settings' => [
        'session.upload_progress.enabled' => read_setting('session.upload_progress.enabled'),
        'memory_limit' => read_setting('memory_limit'),
        'post_max_size' => read_setting('post_max_size'),
        'fatal_error_backtraces' => $isPhp85
            ? read_setting('fatal_error_backtraces')
            : null,
    ],
];

echo json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), "\n";

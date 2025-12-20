<?php
$commands = [
    'whoami'   => 'whoami',
    'uptime'   => 'uptime',
    'disk'     => 'df -h',
    'memory'   => 'free -m',
    'processes'=> 'ps aux',
    'netstat'  => 'netstat -tulpn',
    'ls_root'  => 'ls /',
    'ls_home'  => 'ls /home',
    'php_ver'  => 'php -v'
];

$output = '';

if (isset($_GET['action']) && isset($commands[$_GET['action']])) {
    $output = shell_exec($commands[$_GET['action']] . ' 2>&1');
}
?>
<!DOCTYPE html>
<html>
<head>
    <style>
        body { background:#111; color:#0f0; font-family: monospace; }
        select, button { padding:6px; }
        pre { background:#000; padding:10px; margin-top:10px; }
    </style>
</head>
<body>

<form method="get">
    <select name="action">
        <?php foreach ($commands as $key => $cmd): ?>
            <option value="<?= $key ?>"><?= $key ?></option>
        <?php endforeach; ?>
    </select>
    <button type="submit">Execute</button>
</form>

<pre><?= htmlspecialchars($output) ?></pre>

</body>
</html>

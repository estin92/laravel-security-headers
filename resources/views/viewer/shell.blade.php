<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Security header reports</title>
    @if($styleSrc !== null)
        <link rel="stylesheet" href="{{ $styleSrc }}">
    @endif
</head>
<body>
    <div id="security-headers-viewer" data-base-path="{{ rtrim(config('security-headers.reporting.viewer.path', '/security-headers/reports'), '/') }}"></div>
    <script type="module" src="{{ $scriptSrc }}"></script>
</body>
</html>

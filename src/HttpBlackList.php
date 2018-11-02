<?php

namespace foodette\extension\honeypot;

#use \Yii;

class HttpBlackList
{
    const TYPE_SEARCHENGINE = 0;
    const TYPE_SUSPICIOUS   = 1;

    /**
     * @var string
     */
    public $apiKey;

    /**
     * HttpBlackList constructor.
     * @param String $apiKey (12 characters)
     * @throws \CException
     */
    public function __construct(String $apiKey)
    {
        if (preg_match('/^[a-z]{12}$/', $apiKey)) {
            $this->apiKey = $apiKey;
        } else {
            throw new \CException('You must specify a valid API key.');
        }
    }

    /**
     * @param string $ipAddress
     * @return bool whether ip address passes Http:BL
     * @throws \CException
     */
    public function check(string $ipAddress)
    {
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE)) {
            throw new \CException('Invalid IP address.');
        }

        // Performs the query
        $result = $this->getDnsRecord($ipAddress);
        return $result == $ipAddress;
    }

    /**
     * @param string $ipAddress
     * @throws \CException
     */
    public function query(string $ipAddress)
    {
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE)) {
            throw new \CException('Invalid IP address.');
        }

        // Performs the query
        $result = $this->getDnsRecord($ipAddress);

        $aRet = [];

        if ($result != $ipAddress) {
            // check visitor type
            $aResults = explode('.', $result);
            if ($aResults[0] == 127) {
                $aRet['lastActivity'] = $aResults[1];
                $aRet['threatScore']  = $aResults[2];
                $aRet['type']         = $aResults[3];
            }
        }

        return $aRet;
    }

    /**
     * Get DNS Record
     *
     * Wrapper method for gethostbyname() to allow fo easy mocking of the
     * results in our tests. Takes an already reversed IP address and does a
     * DNS lookup for A records against the http:BL API.
     *
     * @param  string $ipAddress IPv4 address to check
     * @return string IP result from the DNS lookup
     */
    protected function getDnsRecord($ipAddress)
    {
        // Flips the IP address octets
        $octets = explode('.', $ipAddress);
        $reversedIp = implode('.', array_reverse($octets));

        return gethostbyname($this->apiKey . '.' . $reversedIp . '.dnsbl.httpbl.org');
    }
}

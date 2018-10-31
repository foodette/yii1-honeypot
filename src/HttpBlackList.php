<?php

namespace foodette\extension\honeypot;

#use \Yii;

class HttpBlackList
{
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
}

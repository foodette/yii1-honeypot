<?php
use PHPUnit\Framework\TestCase;
use foodette\extension\honeypot\HttpBlackList;

// let Yii::import do the magic
/** @noinspection PhpUnhandledExceptionInspection */
Yii::import('system.base.CException');

class HttpBlackListTest extends TestCase
{
    /**
     * @throws CException
     */
    public function testInvalidApiKey()
    {
        $this->expectException(CException::class);
        new HttpBlackList('');
    }

    /**
     * @throws CException
     */
    public function testValidApiKeyHas12Characters()
    {
        $httpBL = new HttpBlackList('aaabbbcccddd');
        $this->assertEquals('aaabbbcccddd', $httpBL->apiKey);
    }
}

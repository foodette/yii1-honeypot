<?php /** @noinspection PhpUndefinedClassInspection */

use PHPUnit\Framework\TestCase;
use foodette\extension\honeypot\HttpBlackList;

// let Yii::import do the magic
/** @noinspection PhpUnhandledExceptionInspection */
Yii::import('system.base.CException');

class HttpBlackListTest extends TestCase
{
    /**
     * @expectedException           CException
     * @expectedExceptionMessage    You must specify a valid API key.
     */
    public function testInvalidApiKey()
    {
        new HttpBlackList('foo');
    }

    /**
     * @throws CException
     */
    public function testValidApiKeyHas12Characters()
    {
        $httpBL = new HttpBlackList('aaabbbcccddd');
        $this->assertEquals('aaabbbcccddd', $httpBL->apiKey);
    }

    /**
     * @expectedException           CException
     * @expectedExceptionMessage    Invalid IP address.
     */
    public function testInvalidIP()
    {
        $httpBL = new HttpBlackList('aaabbbcccddd');
        $httpBL->query('foo');
    }

    protected function getHttpBLStub()
    {
        return $this->getMockBuilder(HttpBlackList::class)
            ->disableOriginalConstructor()
            ->disableOriginalClone()
            ->disableArgumentCloning()
            ->disallowMockingUnknownTypes()
            ->setMethods(['getDnsRecord'])
            ->getMock();
    }

    public function testMCheckOk()
    {
        // Create a stub for the HttpBlackList class.
        $stub = $this->getHttpBLStub();
        // Configure the stub.
        $stub->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnArgument(0));

        /** @noinspection PhpUndefinedMethodInspection */
        $this->assertTrue($stub->check('1.2.3.4'));
    }

    public function testCheckSuspicious()
    {
        // Create a stub for the HttpBlackList class.
        $stub = $this->getHttpBLStub();
        // Configure the stub.
        $stub->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnValue('127.0.0.1'));

        /** @noinspection PhpUndefinedMethodInspection */
        $this->assertFalse($stub->check('1.2.3.4'));
    }

    public function testQueryNoResults()
    {
        // Create a stub for the HttpBlackList class.
        $stub = $this->getHttpBLStub();
        // Configure the stub.
        $stub->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnArgument(0));

        /** @noinspection PhpUndefinedMethodInspection */
        $this->assertEquals([], $stub->query('1.2.3.4'));
    }

    public function testQuerySuspicious()
    {
        // Create a stub for the HttpBlackList class.
        $stub = $this->getHttpBLStub();
        // Configure the stub.
        $stub->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnValue('127.0.0.1'));

        /** @noinspection PhpUndefinedMethodInspection */
        $aRet = $stub->query('1.2.3.4');
        $this->assertEquals(HttpBlackList::TYPE_SUSPICIOUS, $aRet['type']);
    }

    public function testQueryThreatScore()
    {
        // Create a stub for the HttpBlackList class.
        $stub = $this->getHttpBLStub();
        // Configure the stub.
        $stub->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnValue('127.0.40.1'));

        /** @noinspection PhpUndefinedMethodInspection */
        $aRet = $stub->query('1.2.3.4');
        $this->assertEquals(40, $aRet['threatScore']);
    }

    public function testQueryLastActivity()
    {
        // Create a stub for the HttpBlackList class.
        $stub = $this->getHttpBLStub();
        // Configure the stub.
        $stub->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnValue('127.17.40.1'));

        /** @noinspection PhpUndefinedMethodInspection */
        $aRet = $stub->query('1.2.3.4');
        $this->assertEquals(17, $aRet['lastActivity']);
    }

    /**
     * @throws CException
     */
    public function testRealQueryOnKnownSuspiciousIP()
    {
        $httpBL = new HttpBlackList('hxtidatekhpe');
        $aRet = $httpBL->query('185.136.156.195');
        $this->assertGreaterThanOrEqual(1, $aRet['type']);
        $this->assertGreaterThanOrEqual(1, $aRet['threatScore']);
        $this->assertGreaterThanOrEqual(1, $aRet['lastActivity']);
    }

}

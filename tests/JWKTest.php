<?php

namespace Tests;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

class JWKTest extends BaseTestCase
{
    private static $keys;
    private static $privKey1;
    private static $privKey2;
    public function testMissingKty()
    {
        $this->setExpectedException('Firebase\JWT\Exceptions\UnexpectedValueException', 'JWK must contain a "kty" parameter');
        $badJwk = array('kid' => 'foo');
        $keys = JWK::parseKeySet(array('keys' => array($badJwk)));
    }

    public function testInvalidAlgorithm()
    {
        $this->setExpectedException('Firebase\JWT\Exceptions\UnexpectedValueException', 'No supported algorithms found in JWK Set');
        $badJwk = array('kty' => 'BADALG');
        $keys = JWK::parseKeySet(array('keys' => array($badJwk)));
    }

    public function testParseJwkKeySet()
    {
        $jwkSet = json_decode(file_get_contents(__DIR__ . '/rsa-jwkset.json'), true);
        $keys = JWK::parseKeySet($jwkSet);
        $this->assertTrue(is_array($keys));
        $this->assertArrayHasKey('jwk1', $keys);
        self::$keys = $keys;
    }

    public function testParseJwkKeyEmpty()
    {
        $this->setExpectedException('Firebase\JWT\Exceptions\InvalidArgumentException', 'JWK must not be empty');
        JWK::parseKeySet(array('keys' => array(array())));
    }

    public function testParseJwkKeySetEmpty()
    {
        $this->setExpectedException('Firebase\JWT\Exceptions\InvalidArgumentException', 'JWK Set did not contain any keys');
        JWK::parseKeySet(array('keys' => array()));
    }

    /**
     * @depends testParseJwkKeySet
     */
    public function testDecodeByJwkKeySetTokenExpired()
    {
        $privKey1 = file_get_contents(__DIR__ . '/rsa1-private.pem');
        $payload = array('exp' => strtotime('-1 hour'));
        $msg = JWT::encode($payload, $privKey1, 'RS256', 'jwk1');
        $this->setExpectedException('Firebase\JWT\Exceptions\ExpiredException');
        JWT::decode($msg, self::$keys, array('RS256'));
    }

    /**
     * @depends testParseJwkKeySet
     */
    public function testDecodeByJwkKeySet()
    {
        $privKey1 = file_get_contents(__DIR__ . '/rsa1-private.pem');
        $payload = array('sub' => 'foo', 'exp' => strtotime('+10 seconds'));
        $msg = JWT::encode($payload, $privKey1, 'RS256', 'jwk1');
        $result = JWT::decode($msg, self::$keys, array('RS256'));
        $this->assertEquals("foo", $result->sub);
    }

    /**
     * @depends testParseJwkKeySet
     */
    public function testDecodeByMultiJwkKeySet()
    {
        $privKey2 = file_get_contents(__DIR__ . '/rsa2-private.pem');
        $payload = array('sub' => 'bar', 'exp' => strtotime('+10 seconds'));
        $msg = JWT::encode($payload, $privKey2, 'RS256', 'jwk2');
        $result = JWT::decode($msg, self::$keys, array('RS256'));
        $this->assertEquals("bar", $result->sub);
    }
}

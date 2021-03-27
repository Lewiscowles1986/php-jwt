<?php

namespace Tests;

use PHPUnit\Framework\TestCase;

class BaseTestCase extends TestCase
{
    /*
     * For compatibility with PHPUnit 4.8 and PHP < 5.6
     */
    public function setExpectedException($exceptionName, $message = '', $code = null)
    {
        if (method_exists($this, 'expectException')) {
            $this->expectException($exceptionName);
            if ($message) {
                $this->expectExceptionMessage($message);
            }
        } else {
            parent::setExpectedException($exceptionName, $message, $code);
        }
    }
}

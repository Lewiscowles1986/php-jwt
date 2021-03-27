<?php

namespace JWT\Utils;

class StringUtils
{
    /**
     * Get the number of bytes in cryptographic strings.
     *
     * @param string $str
     *
     * @return int
     */
    public static function safeStrlen($str)
    {
        if (\function_exists('mb_strlen')) {
            return \mb_strlen($str, '8bit');
        }
        return \strlen($str);
    }
}

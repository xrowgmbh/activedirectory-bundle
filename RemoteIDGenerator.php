<?php
/**
 * User: bjoernd
 * Date: 22.02.2018
 * Time: 15:19
 */

namespace Xrow\ActiveDirectoryBundle;

class RemoteIDGenerator
{
    const REMOTEID_PREFIX = 'ActiveDirectory-';
    static function generate( $name ){
        return self::REMOTEID_PREFIX . md5( $name );
    }
    static function validate( $remoteid ){
        preg_match('@^(' . self::REMOTEID_PREFIX . ')(.+)@i', $remoteid, $test);
        if (isset($test[1]) and $test[1] === self::REMOTEID_PREFIX ) {
            return true;
        }
        return false;
    }
}
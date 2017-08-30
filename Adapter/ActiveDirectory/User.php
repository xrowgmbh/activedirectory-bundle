<?php

namespace Xrow\ActiveDirectoryBundle\Adapter\ActiveDirectory;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * A 'generic' LDAP Remote user class.
 * Since this is not a service, we allow all config to be set in the code creating instances of this (i.e. the Client)
 */
class User implements UserInterface
{
    protected $emailField;
    protected $username;
    protected $password;

    /**
     * Most likely to be set at creation time, holds the data coming from the remote system.
     *
     * NB: the whole profile gets serialized in the session, as part of the Sf auth token. You should probably make sure
     * that it does not include a huge amount of useless data, by implementing the Serializable interface...
     *
     * @var mixed
     */
    protected $profile;
    /**
     * @param array $authUserResult (nested array)
     * @param string $emailField the name of the ldap attribute which holds the user email address
     * @param string $login
     * @param string $password
     *
     * @todo decide what to store of $AuthUserResult, so that it can be serialized without taking up too much space
     *       (otoh maybe this never gets serialized, and only the eZ-mvc-user does?
     *       Note that the list of attributes gotten from ladp is decided by settings for the client class...
     * @todo store the password salted and encrypted in memory instead of plaintext
     */
    public function __construct($authUserResult, $login, $password='')
    {
        $this->username = $login;
        $this->password = $password;
        $this->profile = $authUserResult;
    }

    /**
     * SF roles. Important: not to have this empty, otherwise SF will think this user is not an authenticated one
     * @return array
     */
    public function getRoles()
    {
        return array('ROLE_USER');
    }

    /**
     * @todo throw if unset ?
     * @return string
     */
    public function getEmail()
    {
        return $this->profile['mail'];
    }

    public function getProfile()
    {
        return $this->profile;
    }
    
    /**
     * Returns the password used to authenticate the user.
     * @return string The password
     */
    public function getPassword()
    {
        return $this->password;
    }
    
    /**
     * Returns the salt that was originally used to encode the password.
     *
     * This can return null if the password was not encoded using a salt.
     *
     * @return string|null The salt
     */
    public function getSalt()
    {
        return null;
    }
    
    /**
     * Returns the username used to authenticate the user.
     *
     * @return string The username
     */
    public function getUsername()
    {
        return $this->username;
    }
    
    
    public function getRemoteIdFromProfile()
    {
        return \Xrow\ActiveDirectoryBundle\Security\User\RemoteUserHandler::REMOTEID_PREFIX . self::getTextSID($this->profile['objectguid']);
    }
    
    /**
     * Removes sensitive data from the user.
     *
     * This is important if, at any given point, sensitive information like
     * the plain-text password is stored on this object.
     */
    public function eraseCredentials()
    {
    }
    /**
     * Converts a string GUID to a hexdecimal value so it can be queried.
     *
     * @param string $strGUID A string representation of a GUID
     *
     * @return string
     */
    static function strGuidToHex($strGUID)
    {
        $strGUID = str_replace('-', '', $strGUID);
        $octet_str = '\\'.substr($strGUID, 6, 2);
        $octet_str .= '\\'.substr($strGUID, 4, 2);
        $octet_str .= '\\'.substr($strGUID, 2, 2);
        $octet_str .= '\\'.substr($strGUID, 0, 2);
        $octet_str .= '\\'.substr($strGUID, 10, 2);
        $octet_str .= '\\'.substr($strGUID, 8, 2);
        $octet_str .= '\\'.substr($strGUID, 14, 2);
        $octet_str .= '\\'.substr($strGUID, 12, 2);
        $length = (strlen($strGUID) - 2);
        for ($i = 16; $i <= $length; $i++) {
            if (($i % 2) == 0) {
                $octet_str .= '\\'.substr($strGUID, $i, 2);
            }
        }
        return $octet_str;
    }
    /**
     * Convert a binary SID to a text SID.
     *
     * @param string $binsid A Binary SID
     *
     * @return string
     */
    static function getTextSID($binsid)
    {
        $hex_sid = bin2hex($binsid);
        $rev = hexdec(substr($hex_sid, 0, 2));
        $subcount = hexdec(substr($hex_sid, 2, 2));
        $auth = hexdec(substr($hex_sid, 4, 12));
        $result = "$rev-$auth";
        $subauth = [];
        for ($x = 0;$x < $subcount; $x++) {
            $subauth[$x] = hexdec($this->littleEndian(substr($hex_sid, 16 + ($x * 8), 8)));
            $result .= '-'.$subauth[$x];
        }
        // Cheat by tacking on the S-
        return 'S-'.$result;
    }
}

<?php
namespace Xrow\ActiveDirectoryBundle\Adapter\ActiveDirectory;

use Symfony\Component\Security\Core\User\UserInterface;
use Xrow\ActiveDirectoryBundle\RemoteIDGenerator;

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
     *
     * @param array $authUserResult
     *            (nested array)
     * @param string $emailField
     *            the name of the ldap attribute which holds the user email address
     * @param string $login            
     * @param string $password            
     *
     * @todo decide what to store of $AuthUserResult, so that it can be serialized without taking up too much space
     *       (otoh maybe this never gets serialized, and only the eZ-mvc-user does?
     *       Note that the list of attributes gotten from ladp is decided by settings for the client class...
     * @todo store the password salted and encrypted in memory instead of plaintext
     */
    public function __construct($authUserResult, $login, $password = '')
    {
        $this->username = $login;
        $this->password = $password;
        $this->profile = $authUserResult;
    }

    /**
     * SF roles.
     * Important: not to have this empty, otherwise SF will think this user is not an authenticated one
     * 
     * @return array
     */
    public function getRoles()
    {
        return array(
            'ROLE_USER'
        );
    }

    /**
     * @throws Exception if an email address can't be found.
     * @return string email address of profile
     */
    public function getEmail()
    {
        if (isset($this->profile['mail'])){
            return $this->profile['mail'];
        }
        elseif (isset($this->profile['userprincipalname'])){
            return $this->profile['userprincipalname'];
        }
        else{
            throw new \Exception( "Required LDAP Attribute for email isn't found. Did try mail and userprincipalname." );
        }
    }

    public function getProfile()
    {
        return $this->profile;
    }

    /**
     * Returns the password used to authenticate the user.
     * 
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
        return RemoteIDGenerator::generate( self::getTextSID($this->profile['objectguid'] ) );
    }

    /**
     * Removes sensitive data from the user.
     *
     * This is important if, at any given point, sensitive information like
     * the plain-text password is stored on this object.
     */
    public function eraseCredentials()
    {}
}

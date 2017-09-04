<?php
namespace Xrow\ActiveDirectoryBundle\Adapter\LDAP;

interface ClientInterface
{

    /**
     *
     * @param string $login            
     * @param string $password            
     * @return Adldap\Models\User
     * @throws BadCredentialsException|AuthenticationServiceException
     */
    public function authenticateUser($login, $password);
}
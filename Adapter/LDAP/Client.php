<?php

namespace Xrow\ActiveDirectoryBundle\Adapter\LDAP;

use Psr\Log\LoggerInterface;
use Symfony\Component\Ldap\LdapClientInterface;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Xrow\ActiveDirectoryBundle\Adapter\ClientInterface;
use Xrow\ActiveDirectoryBundle\Adapter\ActiveDirectory\User;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;

/**
 * A 'generic' LDAP Client, driven by configuration.
 * It should suffice for most cases.
 * It relies on the Symfony LDAP Component.
 */
class Client implements ClientInterface
{
    protected $ldap;
    protected $logger;
    protected $settings;

    /**
     * @param LdapClientInterface $ldap
     * @param array $settings
     *
     * @todo document the settings
     */
    public function __construct(LdapClientInterface $ldap, array $settings)
    {
        $this->ldap = $ldap;
        $this->settings = $settings;
    }

    /**
     * @param LoggerInterface $logger
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param string $username
     * @param string $password
     * @return RemoteUser
     * @throws BadCredentialsException|AuthenticationServiceException
     */
    public function authenticateUser($username, $password)
    {
        if ($this->logger) $this->logger->info("Looking up remote user: '$username'");

        try {
            $this->ldap->bind($this->settings['search_dn'], $this->settings['search_password']);
            $username = $this->ldap->escape($username, '', LDAP_ESCAPE_FILTER);
            $query = "(sAMAccountName=$username)";
            
            if (isset($this->settings['attributes']) && count($this->settings['attributes'])) {
                $search = $this->ldap->find($this->settings['base_dn'], $query, $this->settings['attributes']);
            } else {
                $search = $this->ldap->find($this->settings['base_dn'], $query);
            }

        } catch (ConnectionException $e) {
            if ($this->logger) $this->logger->error(sprintf('Connection error "%s"', $e->getMessage()));

            /// @todo shall we log an error ?
            throw new AuthenticationServiceException(sprintf('Connection error "%s"', $e->getMessage()), 0, $e);
        } catch (\Exception $e) {
            if ($this->logger) $this->logger->info("Authentication failed for user: '$username': ".$e->getMessage());
            throw new BadCredentialsException('The presented password is invalid.');
        }
        if ($this->logger) $this->logger->info("Authentication succeeded for user: '$username'");
        
        if (!$search) {
            if ($this->logger) $this->logger->info("User not found");

            throw new BadCredentialsException(sprintf('User "%s" not found.', $username));
        }

        if ($search['count'] > 1) {
            if ($this->logger) $this->logger->warning('More than one ldap account found for ' . $username);

            throw new AuthenticationServiceException('More than one user found');
        }

        try {
            $this->validateLdapResults($search[0]);
        } catch (\Exception $e) {
            if ($this->logger) $this->logger->warning('Invalid user profile for user: \'$username\': '.$e->getMessage());

            throw new AuthenticationServiceException('Invalid user profile: '.$e->getMessage());
        }

        if ($this->logger) $this->logger->info("Remote user found: '$username'");
        // allow ldap to give us back the actual login field to be used in eZ. It might be different because of dashes, spaces, case...
        if ( isset($search[0]["userprincipalname"][0])) {
            if ($username != $search[0]["userprincipalname"][0]) {
                if ($this->logger) $this->logger->info("Renamed user '$username' to '{$search[0][$this->settings["userprincipalname"]][0]}'");

                $username = $search[0]["userprincipalname"][0];
            }
        }

        return new User($search[0], $username, $password);
    }

    /**
     * To be overridden in subclasses. Validates the ldap results so that later user creation/update shall not fail
     * @param array $data
     * @return null
     * @throw \Exception
     */
    protected function validateLdapResults(array $data)
    {
        var_dump($data);
    }
}

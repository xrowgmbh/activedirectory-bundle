<?php
namespace Xrow\ActiveDirectoryBundle\Adapter\LDAP;

use Psr\Log\LoggerInterface;
use Adldap\Adldap;
use Symfony\Component\Ldap\Exception\ConnectionException;
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
     *
     * @param LdapClientInterface $ldap            
     * @param array $settings            
     *
     * @todo document the settings
     */
    public function __construct(array $settings = array())
    {
        $this->settings = $settings;
        $this->settings['account_suffix'] = "@" . $this->settings['account_suffix'];
        $this->ldap = new \Adldap\Adldap();
        $this->ldap->addProvider($this->settings);
    }

    /**
     *
     * @param LoggerInterface $logger            
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * Domain Suffix
     * return string domain suffix e.g.
     * @xrow.lan
     */
    public function getAccountSuffix()
    {
        return $this->settings['account_suffix'];
    }

    /**
     *
     * @return Adldap\Models\User
     * @throws BadCredentialsException|AuthenticationServiceException
     */
    public function authenticateUser($username, $password)
    {
        if ($this->logger)
            $this->logger->info("Looking up remote user: '$username'");
        
        try {
            $provider = $this->ldap->connect(null, $username, $password);
        } catch (\Adldap\Auth\BindException $e) {
            if ($this->logger)
                $this->logger->error(sprintf('Connection error "%s"', $e->getMessage()));
            throw new AuthenticationServiceException(sprintf('Connection error "%s"', $e->getMessage()), 0, $e);
        } catch (\Exception $e) {
            if ($this->logger)
                $this->logger->info("Authentication failed for user: '$username': " . $e->getMessage());
            throw new BadCredentialsException('The presented password is invalid.');
        }
        if ($this->logger)
            $this->logger->info("Authentication succeeded for user: '$username'");
        $user = $provider->search()->find($username);
        if (! $user) {
            if ($this->logger)
                $this->logger->info("User not found");
            throw new BadCredentialsException(sprintf('User "%s" not found.', $username));
        }
        return $user;
    }
}

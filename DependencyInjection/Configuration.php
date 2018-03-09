<?php
namespace Xrow\ActiveDirectoryBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files.
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/configuration.html}
 */
class Configuration implements ConfigurationInterface
{

    /**
     *
     * {@inheritdoc}
     *
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('xrow_active_directory');
        $rootNode->children()
            ->scalarNode('account_prefix')
            ->info('The domain prefix as in prefix-domainname\user')
            ->end()
            ->scalarNode('account_suffix')
            ->info('The domain suffix as in user@domain.suffix')
            ->end()
            ->arrayNode('domain_controllers')
            ->isRequired()
            ->info('The domain controllers option is an array of your LDAP hosts. You can use the either the host name or the IP address of your host.')
            ->prototype('scalar')
            ->end()
            ->end()
            ->scalarNode('base_dn')
            ->isRequired()
            ->info('The base distinguished name of your domain. Example: DC=corp,DC=acme,DC=org')
            ->end()
            ->end();
        
        return $treeBuilder;
    }
}

<?php

/**
 * File containing the SecurityPass class.
 *
 * @copyright Copyright (C) eZ Systems AS. All rights reserved.
 * @license For full copyright and license information view LICENSE file distributed with this source code.
 */
namespace Xrow\ActiveDirectoryBundle\DependencyInjection\Compiler;

use Xrow\ActiveDirectoryBundle\Security\Authentication\Provider\ActiveDirectoryProvider as AuthenticationProvider;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Security related compiler pass.
 * Manipulates Symfony core security services to adapt them to eZ security needs.
 */
class SecurityPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {

        $userhandlerRef = new Reference('active_directory.remoteuser_handler');
        $configResolverRef = new Reference('ezpublish.config.resolver');
        $repositoryReference = new Reference('ezpublish.api.repository');
        
        // Override and inject the ez Platform default authentication provider https://github.com/ezsystems/ezpublish-kernel/blob/master/eZ/Bundle/EzPublishCoreBundle/DependencyInjection/Compiler/SecurityPass.php.
        $daoAuthenticationProviderDef = $container->findDefinition('security.authentication.provider.dao');
        $daoAuthenticationProviderDef->setClass(AuthenticationProvider::class);
        #$daoAuthenticationProviderDef->addArgument($userhandlerRef);
        $daoAuthenticationProviderDef->addMethodCall(
            'setRepository',
            array($repositoryReference)
            );
        $daoAuthenticationProviderDef->addMethodCall(
            'setUserHandler',
            array($userhandlerRef)
            );
    }
}
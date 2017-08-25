<?php

namespace Xrow\ActiveDirectoryBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Xrow\ActiveDirectoryBundle\DependencyInjection\Compiler\SecurityPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class XrowActiveDirectoryBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);
        $container->addCompilerPass(new SecurityPass());
        
    }
}

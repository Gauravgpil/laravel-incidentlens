<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens\Tests;

use Gaurav\IncidentLens\IncidentLensServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            IncidentLensServiceProvider::class,
        ];
    }
}

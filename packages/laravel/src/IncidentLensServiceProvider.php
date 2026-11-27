<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens;

use Gaurav\IncidentLens\Commands\DoctorCommand;
use Gaurav\IncidentLens\Commands\ScanCommand;
use Gaurav\IncidentLens\Commands\StatusCommand;
use Gaurav\IncidentLens\Engine\EngineClient;
use Gaurav\IncidentLens\Support\ProjectInspector;
use Illuminate\Support\ServiceProvider;

final class IncidentLensServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/incidentlens.php', 'incidentlens');

        $this->app->singleton(ProjectInspector::class, function ($app): ProjectInspector {
            return new ProjectInspector($app, $app->make('config'));
        });

        $this->app->singleton(EngineClient::class, function ($app): EngineClient {
            $config = $app->make('config');
            $binary = $config->get('incidentlens.engine.binary');
            $timeout = (int) $config->get('incidentlens.engine.timeout', 120);

            return new EngineClient(
                is_string($binary) ? $binary : null,
                $timeout > 0 ? $timeout : 120,
                $app->basePath()
            );
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/incidentlens.php' => config_path('incidentlens.php'),
            ], 'incidentlens-config');

            $this->commands([
                DoctorCommand::class,
                StatusCommand::class,
                ScanCommand::class,
            ]);
        }
    }
}

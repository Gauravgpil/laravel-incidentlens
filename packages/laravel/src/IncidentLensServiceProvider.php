<?php

declare(strict_types=1);

namespace Gaurav\IncidentLens;

use Gaurav\IncidentLens\Collectors\RuntimeCollector;
use Gaurav\IncidentLens\Commands\AuditCommand;
use Gaurav\IncidentLens\Commands\DoctorCommand;
use Gaurav\IncidentLens\Commands\IncidentLensCommand;
use Gaurav\IncidentLens\Commands\InstallCommand;
use Gaurav\IncidentLens\Commands\ScanCommand;
use Gaurav\IncidentLens\Commands\SecurityAuditCommand;
use Gaurav\IncidentLens\Commands\StatusCommand;
use Gaurav\IncidentLens\Engine\EngineClient;
use Gaurav\IncidentLens\Support\ProjectInspector;
use Illuminate\Contracts\Events\Dispatcher;
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
        $config = $this->app->make('config');
        if ((bool) $config->get('incidentlens.enabled', true) && (bool) $config->get('incidentlens.runtime.enabled', false)) {
            $storagePath = (string) ($config->get('incidentlens.storage.path') ?? storage_path('app/incidentlens'));
            $collector = new RuntimeCollector(
                $storagePath,
                (float) $config->get('incidentlens.performance.sampling_rate', 1.0),
                (bool) $config->get('incidentlens.database.capture_queries', false),
                (bool) $config->get('incidentlens.queue.enabled', true),
                (bool) $config->get('incidentlens.database.detect_lazy_loading', false),
                $this->app->basePath(),
            );
            $collector->register($this->app->make(Dispatcher::class));
        }

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/incidentlens.php' => config_path('incidentlens.php'),
            ], 'incidentlens-config');

            $this->commands([
                AuditCommand::class,
                DoctorCommand::class,
                IncidentLensCommand::class,
                InstallCommand::class,
                SecurityAuditCommand::class,
                StatusCommand::class,
                ScanCommand::class,
            ]);
        }
    }
}

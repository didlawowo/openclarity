// Copyright © 2023 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/openclarity/vmclarity/api/models"
	"github.com/openclarity/vmclarity/pkg/orchestrator/assetscanestimationwatcher"
	"github.com/openclarity/vmclarity/pkg/orchestrator/assetscanprocessor"
	"github.com/openclarity/vmclarity/pkg/orchestrator/assetscanwatcher"
	"github.com/openclarity/vmclarity/pkg/orchestrator/discovery"
	"github.com/openclarity/vmclarity/pkg/orchestrator/scanconfigwatcher"
	"github.com/openclarity/vmclarity/pkg/orchestrator/scanestimationwatcher"
	"github.com/openclarity/vmclarity/pkg/orchestrator/scanwatcher"
)

const (
	APIServerHost       = "APISERVER_HOST"
	APIServerDisableTLS = "APISERVER_DISABLE_TLS"
	APIServerPort       = "APISERVER_PORT"
	HealthCheckAddress  = "HEALTH_CHECK_ADDRESS"

	DeleteJobPolicy               = "DELETE_JOB_POLICY"
	ScannerContainerImage         = "SCANNER_CONTAINER_IMAGE"
	GitleaksBinaryPath            = "GITLEAKS_BINARY_PATH"
	ClamBinaryPath                = "CLAM_BINARY_PATH"
	FreshclamBinaryPath           = "FRESHCLAM_BINARY_PATH"
	AlternativeFreshclamMirrorURL = "ALTERNATIVE_FRESHCLAM_MIRROR_URL"
	LynisInstallPath              = "LYNIS_INSTALL_PATH"
	ScannerAPIServerAddress       = "SCANNER_VMCLARITY_APISERVER_ADDRESS"
	ExploitDBAddress              = "EXPLOIT_DB_ADDRESS"
	TrivyServerAddress            = "TRIVY_SERVER_ADDRESS"
	TrivyServerTimeout            = "TRIVY_SERVER_TIMEOUT"
	GrypeServerAddress            = "GRYPE_SERVER_ADDRESS"
	GrypeServerTimeout            = "GRYPE_SERVER_TIMEOUT"
	ChkrootkitBinaryPath          = "CHKROOTKIT_BINARY_PATH"

	ScanConfigPollingInterval  = "SCAN_CONFIG_POLLING_INTERVAL"
	ScanConfigReconcileTimeout = "SCAN_CONFIG_RECONCILE_TIMEOUT"

	ScanPollingInterval  = "SCAN_POLLING_INTERVAL"
	ScanReconcileTimeout = "SCAN_RECONCILE_TIMEOUT"
	ScanTimeout          = "SCAN_TIMEOUT"

	ScanEstimationPollingInterval  = "SCAN_ESTIMATION_POLLING_INTERVAL"
	ScanEstimationReconcileTimeout = "SCAN_ESTIMATION_RECONCILE_TIMEOUT"
	ScanEstimationTimeout          = "SCAN_ESTIMATION_TIMEOUT"

	AssetScanEstimationPollingInterval  = "ASSET_SCAN_ESTIMATION_POLLING_INTERVAL"
	AssetScanEstimationReconcileTimeout = "ASSET_SCAN_ESTIMATION_RECONCILE_TIMEOUT"
	AssetScanEstimationAbortTimeout     = "ASSET_SCAN_ESTIMATION_ABORT_TIMEOUT"

	AssetScanPollingInterval  = "ASSET_SCAN_POLLING_INTERVAL"
	AssetScanReconcileTimeout = "ASSET_SCAN_RECONCILE_TIMEOUT"
	AssetScanAbortTimeout     = "ASSET_SCAN_ABORT_TIMEOUT" // nolint:gosec

	AssetScanProcessorPollingInterval  = "ASSET_SCAN_PROCESSOR_POLLING_INTERVAL"
	AssetScanProcessorReconcileTimeout = "ASSET_SCAN_PROCESSOR_RECONCILE_TIMEOUT"

	DiscoveryInterval = "DISCOVERY_INTERVAL"

	ControllerStartupDelay = "CONTROLLER_STARTUP_DELAY"

	ProviderKind = "PROVIDER"
)

const (
	DefaultTrivyServerTimeout = 5 * time.Minute
	DefaultGrypeServerTimeout = 2 * time.Minute

	// Approximately half the polling delay to allow for more efficient
	// reconcile cascading e.g. reconciling scan config creates a scan, the
	// poller for scan is offset by 7 seconds so should pick up the new
	// scan after 7 seconds instead of the full poller time.
	DefaultControllerStartupDelay = 7 * time.Second
	DefaultProviderKind           = models.AWS
)

type Config struct {
	ProviderKind models.CloudProvider

	APIServerHost      string `json:"apiserver-host,omitempty"`
	APIServerPort      int    `json:"apiserver-port,omitempty"`
	HealthCheckAddress string `json:"health-check-address,omitempty"`

	// The Orchestrator starts the Controller(s) in a sequence and the ControllerStartupDelay is used for waiting
	// before starting each Controller to avoid them hitting the API at the same time and allow one Controller
	// to pick up an event generated by the other without waiting until the next polling cycle.
	ControllerStartupDelay time.Duration

	DiscoveryConfig                  discovery.Config
	ScanConfigWatcherConfig          scanconfigwatcher.Config
	ScanWatcherConfig                scanwatcher.Config
	AssetScanWatcherConfig           assetscanwatcher.Config
	AssetScanEstimationWatcherConfig assetscanestimationwatcher.Config
	ScanEstimationWatcherConfig      scanestimationwatcher.Config
	AssetScanProcessorConfig         assetscanprocessor.Config
}

func setConfigDefaults() {
	viper.SetDefault(HealthCheckAddress, ":8082")
	viper.SetDefault(DeleteJobPolicy, string(assetscanwatcher.DeleteJobPolicyAlways))
	// https://github.com/openclarity/vmclarity-tools-base/blob/main/Dockerfile#L33
	viper.SetDefault(GitleaksBinaryPath, "/artifacts/gitleaks")
	// https://github.com/openclarity/vmclarity-tools-base/blob/main/Dockerfile#L35
	viper.SetDefault(LynisInstallPath, "/artifacts/lynis")
	// https://github.com/openclarity/vmclarity-tools-base/blob/main/Dockerfile
	viper.SetDefault(ChkrootkitBinaryPath, "/artifacts/chkrootkit")
	viper.SetDefault(ClamBinaryPath, "clamscan")
	viper.SetDefault(FreshclamBinaryPath, "freshclam")
	viper.SetDefault(TrivyServerTimeout, DefaultTrivyServerTimeout)
	viper.SetDefault(GrypeServerTimeout, DefaultGrypeServerTimeout)
	viper.SetDefault(ScanConfigPollingInterval, scanconfigwatcher.DefaultPollInterval.String())
	viper.SetDefault(ScanConfigReconcileTimeout, scanconfigwatcher.DefaultReconcileTimeout.String())
	viper.SetDefault(ScanPollingInterval, scanwatcher.DefaultPollInterval.String())
	viper.SetDefault(ScanReconcileTimeout, scanwatcher.DefaultReconcileTimeout.String())
	viper.SetDefault(ScanTimeout, scanwatcher.DefaultScanTimeout.String())
	viper.SetDefault(AssetScanPollingInterval, assetscanwatcher.DefaultPollInterval.String())
	viper.SetDefault(AssetScanReconcileTimeout, assetscanwatcher.DefaultReconcileTimeout.String())
	viper.SetDefault(AssetScanProcessorPollingInterval, assetscanprocessor.DefaultPollInterval.String())
	viper.SetDefault(AssetScanProcessorReconcileTimeout, assetscanprocessor.DefaultReconcileTimeout.String())
	viper.SetDefault(DiscoveryInterval, discovery.DefaultInterval.String())
	viper.SetDefault(ControllerStartupDelay, DefaultControllerStartupDelay.String())
	viper.SetDefault(ProviderKind, DefaultProviderKind)
	viper.SetDefault(AssetScanAbortTimeout, assetscanwatcher.DefaultAbortTimeout)

	viper.SetDefault(AssetScanEstimationAbortTimeout, assetscanestimationwatcher.DefaultAbortTimeout)
	viper.SetDefault(AssetScanEstimationReconcileTimeout, assetscanestimationwatcher.DefaultReconcileTimeout)
	viper.SetDefault(AssetScanEstimationPollingInterval, assetscanestimationwatcher.DefaultPollInterval)

	viper.SetDefault(ScanEstimationReconcileTimeout, scanestimationwatcher.DefaultReconcileTimeout)
	viper.SetDefault(ScanEstimationTimeout, scanestimationwatcher.DefaultScanEstimationTimeout)
	viper.SetDefault(ScanEstimationPollingInterval, scanestimationwatcher.DefaultPollInterval)

	viper.AutomaticEnv()
}

func LoadConfig() (*Config, error) {
	setConfigDefaults()

	var providerKind models.CloudProvider
	switch strings.ToLower(viper.GetString(ProviderKind)) {
	case strings.ToLower(string(models.Azure)):
		providerKind = models.Azure
	case strings.ToLower(string(models.GCP)):
		providerKind = models.GCP
	case strings.ToLower(string(models.Docker)):
		providerKind = models.Docker
	case strings.ToLower(string(models.External)):
		providerKind = models.External
	case strings.ToLower(string(models.Kubernetes)):
		providerKind = models.Kubernetes
	case strings.ToLower(string(models.AWS)):
		fallthrough
	default:
		providerKind = models.AWS
	}

	apiServerHost := viper.GetString(APIServerHost)
	apiServerPort := viper.GetInt(APIServerPort)

	scannerAPIServerAddress := viper.GetString(ScannerAPIServerAddress)
	if scannerAPIServerAddress == "" {
		scannerAPIServerAddress = fmt.Sprintf("http://%s%s", net.JoinHostPort(apiServerHost, strconv.Itoa(apiServerPort)), "/api")
	}

	exploitDBAddress := viper.GetString(ExploitDBAddress)
	if exploitDBAddress == "" {
		exploitDBAddress = fmt.Sprintf("http://%s", net.JoinHostPort(apiServerHost, "1326"))
	}

	c := &Config{
		APIServerHost:          apiServerHost,
		APIServerPort:          apiServerPort,
		HealthCheckAddress:     viper.GetString(HealthCheckAddress),
		ProviderKind:           providerKind,
		ControllerStartupDelay: viper.GetDuration(ControllerStartupDelay),
		DiscoveryConfig: discovery.Config{
			DiscoveryInterval: viper.GetDuration(DiscoveryInterval),
		},
		ScanConfigWatcherConfig: scanconfigwatcher.Config{
			PollPeriod:       viper.GetDuration(ScanConfigPollingInterval),
			ReconcileTimeout: viper.GetDuration(ScanConfigReconcileTimeout),
		},
		ScanWatcherConfig: scanwatcher.Config{
			PollPeriod:       viper.GetDuration(ScanPollingInterval),
			ReconcileTimeout: viper.GetDuration(ScanReconcileTimeout),
			ScanTimeout:      viper.GetDuration(ScanTimeout),
		},
		AssetScanWatcherConfig: assetscanwatcher.Config{
			PollPeriod:       viper.GetDuration(AssetScanPollingInterval),
			ReconcileTimeout: viper.GetDuration(AssetScanReconcileTimeout),
			AbortTimeout:     viper.GetDuration(AssetScanAbortTimeout),
			ScannerConfig: assetscanwatcher.ScannerConfig{
				DeleteJobPolicy:               assetscanwatcher.GetDeleteJobPolicyType(viper.GetString(DeleteJobPolicy)),
				ScannerImage:                  viper.GetString(ScannerContainerImage),
				ScannerBackendAddress:         scannerAPIServerAddress,
				GitleaksBinaryPath:            viper.GetString(GitleaksBinaryPath),
				LynisInstallPath:              viper.GetString(LynisInstallPath),
				ExploitsDBAddress:             exploitDBAddress,
				ClamBinaryPath:                viper.GetString(ClamBinaryPath),
				FreshclamBinaryPath:           viper.GetString(FreshclamBinaryPath),
				AlternativeFreshclamMirrorURL: viper.GetString(AlternativeFreshclamMirrorURL),
				TrivyServerAddress:            viper.GetString(TrivyServerAddress),
				TrivyServerTimeout:            viper.GetDuration(TrivyServerTimeout),
				GrypeServerAddress:            viper.GetString(GrypeServerAddress),
				GrypeServerTimeout:            viper.GetDuration(GrypeServerTimeout),
				ChkrootkitBinaryPath:          viper.GetString(ChkrootkitBinaryPath),
			},
		},
		AssetScanProcessorConfig: assetscanprocessor.Config{
			PollPeriod:       viper.GetDuration(AssetScanProcessorPollingInterval),
			ReconcileTimeout: viper.GetDuration(AssetScanProcessorReconcileTimeout),
		},
		ScanEstimationWatcherConfig: scanestimationwatcher.Config{
			PollPeriod:            viper.GetDuration(ScanEstimationPollingInterval),
			ReconcileTimeout:      viper.GetDuration(ScanEstimationReconcileTimeout),
			ScanEstimationTimeout: viper.GetDuration(ScanEstimationTimeout),
		},
		AssetScanEstimationWatcherConfig: assetscanestimationwatcher.Config{
			PollPeriod:       viper.GetDuration(AssetScanEstimationPollingInterval),
			ReconcileTimeout: viper.GetDuration(AssetScanEstimationReconcileTimeout),
		},
	}

	return c, nil
}

package exporter

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethpandaops/beacon/pkg/beacon"
	"github.com/ethpandaops/ethereum-metrics-exporter/pkg/exporter/disk"
	"github.com/ethpandaops/ethereum-metrics-exporter/pkg/exporter/execution"
	"github.com/ethpandaops/ethereum-metrics-exporter/pkg/exporter/zilliqa"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// Exporter defines the Ethereum Metrics Exporter interface
type Exporter interface {
	// Init initialises the exporter
	Init(ctx context.Context) error
	// Config returns the configuration of the exporter
	Config(ctx context.Context) *Config
	// Serve starts the metrics server
	Serve(ctx context.Context, port int) error
}

// NewExporter returns a new Exporter instance
func NewExporter(log logrus.FieldLogger, conf *Config) Exporter {
	return &exporter{
		log:       log.WithField("component", "exporter"),
		config:    conf,
		namespace: "eth",
	}
}

type exporter struct {
	// Helpers
	namespace string
	log       logrus.FieldLogger
	config    *Config

	// Exporters
	execution execution.Node
	diskUsage disk.UsageMetrics
	zilliqa   *zilliqa.Metrics

	// Clients
	beacon beacon.Node
}

func (e *exporter) Init(ctx context.Context) error {
	e.log.Info("Initializing...")

	if e.config.Execution.Enabled {
		e.log.WithField("modules", strings.Join(e.config.Execution.Modules, ", ")).Info("Initializing execution...")

		executionNode, err := execution.NewExecutionNode(
			ctx,
			e.log.WithField("exporter", "execution"),
			fmt.Sprintf("%s_exe", e.namespace),
			e.config.Execution.Name,
			e.config.Execution.URL,
			e.config.Execution.Modules,
		)
		if err != nil {
			return err
		}

		if err := executionNode.Bootstrap(ctx); err != nil {
			e.log.WithError(err).Error("failed to bootstrap execution node")
		}

		e.execution = executionNode
	}

	if e.config.DiskUsage.Enabled {
		e.log.Info("Initializing disk usage...")

		interval := e.config.DiskUsage.Interval.Duration
		if interval == 0 {
			interval = 60 * time.Minute
		}

		diskUsage, err := disk.NewUsage(
			ctx,
			e.log.WithField("exporter", "disk"),
			fmt.Sprintf("%s_disk", e.namespace),
			e.config.DiskUsage.Directories,
			interval,
		)
		if err != nil {
			return err
		}

		e.diskUsage = diskUsage
	}

	// Initialize Zilliqa exporter
	if e.config.Zilliqa.Enabled {
		e.log.Info("Initializing Zilliqa metrics...")

		zilliqaConfig := &zilliqa.Config{
			Enabled:         e.config.Zilliqa.Enabled,
			RPCURL:          e.config.Zilliqa.RPCURL,
			DepositContract: e.config.GetZilliqaDepositContract(),
			Interval:   		 e.config.Zilliqa.Interval,
		}

		zilliqaExporter, err := zilliqa.NewFromConfig(zilliqaConfig, e.log.WithField("exporter", "zilliqa"), e.config.Debug)
		if err != nil {
			return err
		}

		e.zilliqa = zilliqaExporter
	}

	return nil
}

func (e *exporter) Config(ctx context.Context) *Config {
	return e.config
}

func (e *exporter) Serve(ctx context.Context, port int) error {
	e.log.
		WithField("consensus_url", e.config.Consensus.URL).
		WithField("execution_url", e.config.Execution.URL).
		WithField("zilliqa_url", e.config.Zilliqa.RPCURL).
		Info(fmt.Sprintf("Starting metrics server on :%v", port))

	s := &http.Server{
		Addr:              fmt.Sprintf(":%v", port),
		ReadHeaderTimeout: 30 * time.Second,
	}

	// Register Zilliqa metrics - this is the missing piece!
	if e.config.Zilliqa.Enabled {
		e.log.Info("Registering Zilliqa metrics with Prometheus")
		// Create a new registry for Zilliqa metrics
		zilliqaRegistry := prometheus.NewRegistry()
		e.zilliqa.Register(zilliqaRegistry)
		
		// Merge with existing metrics by using a custom handler
		http.Handle("/metrics", promhttp.HandlerFor(
			prometheus.Gatherers{prometheus.DefaultGatherer, zilliqaRegistry},
			promhttp.HandlerOpts{},
		))
	} else {
		// Use default registry if Zilliqa is disabled
		http.Handle("/metrics", promhttp.Handler())
	}

	go func() {
		err := s.ListenAndServe()
		if err != nil {
			e.log.Fatal(err)
		}
	}()

	if e.config.Execution.Enabled {
		e.log.WithField("execution_url", e.execution.URL()).Info("Starting execution metrics...")

		go e.execution.StartMetrics(ctx)
	}

	if e.config.DiskUsage.Enabled {
		e.log.Info("Starting disk usage metrics...")

		go e.diskUsage.StartAsync(ctx)
	}

	if e.config.Consensus.Enabled {
		e.log.WithField("consensus_url", e.config.Consensus.URL).Info("Starting consensus metrics...")

		if err := e.bootstrapConsensusClients(ctx); err != nil {
			e.log.WithError(err).Error("failed to bootstrap consensus clients")

			return err
		}

		go e.beacon.StartAsync(ctx)
	}

	// Start Zilliqa metrics collection
	if e.config.Zilliqa.Enabled {
		e.log.WithField("zilliqa_url", e.config.Zilliqa.RPCURL).Info("Starting Zilliqa metrics...")

		go e.zilliqa.Start(ctx)
	}

	return nil
}

func (e *exporter) bootstrapConsensusClients(_ context.Context) error {
	opts := *beacon.DefaultOptions().
		EnablePrometheusMetrics()

	if e.config.Consensus.EventStream.Enabled != nil && *e.config.Consensus.EventStream.Enabled {
		opts.BeaconSubscription.Topics = e.config.Consensus.EventStream.Topics

		if len(opts.BeaconSubscription.Topics) == 0 {
			opts.EnableDefaultBeaconSubscription()
		}

		e.log.WithField(
			"topics", strings.Join(opts.BeaconSubscription.Topics, ", "),
		).Info("Enabling beacon event stream with topics...")

		opts.BeaconSubscription.Enabled = true
	}

	e.beacon = beacon.NewNode(e.log, &beacon.Config{
		Addr: e.config.Consensus.URL,
		Name: e.config.Consensus.Name,
	}, "eth_con", opts)

	return nil
}
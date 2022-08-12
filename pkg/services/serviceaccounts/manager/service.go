package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/serviceaccounts"
	"github.com/grafana/grafana/pkg/services/serviceaccounts/api"
	"github.com/grafana/grafana/pkg/services/serviceaccounts/database"
	"github.com/grafana/grafana/pkg/setting"
)

const metricsCollectionInterval = time.Minute * 30

type ServiceAccountsService struct {
	store serviceaccounts.Store
	log   log.Logger
}

func ProvideServiceAccountsService(
	cfg *setting.Cfg,
	ac accesscontrol.AccessControl,
	routeRegister routing.RouteRegister,
	usageStats usagestats.Service,
	serviceAccountsStore serviceaccounts.Store,
	permissionService accesscontrol.ServiceAccountPermissionsService,
) (*ServiceAccountsService, error) {
	database.InitMetrics()
	s := &ServiceAccountsService{
		store: serviceAccountsStore,
		log:   log.New("serviceaccounts"),
	}

	if err := RegisterRoles(ac); err != nil {
		s.log.Error("Failed to register roles", "error", err)
	}

	usageStats.RegisterMetricsFunc(s.store.GetUsageMetrics)

	serviceaccountsAPI := api.NewServiceAccountsAPI(cfg, s, ac, routeRegister, s.store, permissionService)
	serviceaccountsAPI.RegisterAPIEndpoints()

	return s, nil
}

func (sa *ServiceAccountsService) Run(ctx context.Context) error {
	sa.log.Debug("Started Service Account background service")

	if _, err := sa.store.GetUsageMetrics(ctx); err != nil {
		sa.log.Warn("Failed to get usage metrics", "error", err.Error())
	}

	updateStatsTicker := time.NewTicker(metricsCollectionInterval)
	defer updateStatsTicker.Stop()

	for {
		select {
		case <-updateStatsTicker.C:
			if _, err := sa.store.GetUsageMetrics(ctx); err != nil {
				sa.log.Warn("Failed to get usage metrics", "error", err.Error())
			}
		case <-ctx.Done():
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("closing context error in service account background service: %w", ctx.Err())
			}

			return nil
		}
	}
}

func (sa *ServiceAccountsService) CreateServiceAccount(ctx context.Context, orgID int64, saForm *serviceaccounts.CreateServiceAccountForm) (*serviceaccounts.ServiceAccountDTO, error) {
	return sa.store.CreateServiceAccount(ctx, orgID, saForm)
}

func (sa *ServiceAccountsService) DeleteServiceAccount(ctx context.Context, orgID, serviceAccountID int64) error {
	return sa.store.DeleteServiceAccount(ctx, orgID, serviceAccountID)
}

func (sa *ServiceAccountsService) RetrieveServiceAccountIdByName(ctx context.Context, orgID int64, name string) (int64, error) {
	return sa.store.RetrieveServiceAccountIdByName(ctx, orgID, name)
}

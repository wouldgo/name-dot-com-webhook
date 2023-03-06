package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/namedotcom/go/namecom"

	_ "github.com/breml/rootcerts"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	nameDotComDnsProviderSolver := &nameDotComDNSProviderSolver{}
	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName, nameDotComDnsProviderSolver)
}

// nameDotComDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type nameDotComDNSProviderSolver struct {
	client kubernetes.Clientset

	nameDotComClient *namecom.NameCom
}

type secretRefType struct {
	Name      *string `json:"name"`
	Namespace *string `json:"namespace"`
}

// nameDotComDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type nameDotComDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	UserName  *string        `json:"username"`
	Token     *string        `json:"token"`
	SecretRef *secretRefType `json:"secretMapRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *nameDotComDNSProviderSolver) Name() string {
	return "name-dot-com-solver"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *nameDotComDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	host := extractRecordName(ch.ResolvedFQDN, ch.ResolvedZone)
	domainName := ch.ResolvedZone[:len(ch.ResolvedZone)-1]

	klog.Infof("Creating TXT record for %s", domainName)
	cfg, err := c.loadConfig(ch.Config)
	if err != nil {
		return err
	}

	if c.nameDotComClient == nil {

		c.nameDotComClient = namecom.New(*cfg.UserName, *cfg.Token)
	}

	newRecord := &namecom.Record{
		Type:       "TXT",
		Host:       host,
		DomainName: domainName,
		Answer:     ch.Key,
		TTL:        300,
	}

	_, err = c.nameDotComClient.CreateRecord(newRecord)
	if err != nil {

		klog.Errorf("TXT record creation for %s in error: %s", domainName, err.Error())
		return err
	}

	klog.Infof("TXT record for %s created", domainName)
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *nameDotComDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	domainName := ch.ResolvedZone[:len(ch.ResolvedZone)-1]
	host := extractRecordName(ch.ResolvedFQDN, ch.ResolvedZone)

	klog.Infof("Removing TXT record for %s", domainName)
	cfg, err := c.loadConfig(ch.Config)
	if err != nil {
		return err
	}

	if c.nameDotComClient == nil {

		c.nameDotComClient = namecom.New(*cfg.UserName, *cfg.Token)
	}

	listReq := &namecom.ListRecordsRequest{
		DomainName: domainName,
	}

	listRecordResponse, listErr := c.nameDotComClient.ListRecords(listReq)
	if listErr != nil {

		klog.Errorf("TXT record deletion for %s in error: %s", domainName, listErr.Error())
		return listErr
	}

	var recordIdentifier int32
	for _, aRecord := range listRecordResponse.Records {
		if aRecord.Type == "TXT" &&
			aRecord.Host == host &&
			aRecord.Answer == ch.Key {

			recordIdentifier = aRecord.ID
		}
	}
	deleteReq := &namecom.DeleteRecordRequest{
		ID:         recordIdentifier,
		DomainName: domainName,
	}

	_, deleteErr := c.nameDotComClient.DeleteRecord(deleteReq)
	if deleteErr != nil {

		klog.Errorf("TXT record deletion for %s in error: %s", domainName, deleteErr.Error())
		return deleteErr
	}

	klog.Infof("TXT record for %s deleted", domainName)
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *nameDotComDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	klog.Infof("Initializing %s", c.Name())
	clientset, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	klog.Infof("K8s client initialized with %+v", kubeClientConfig)
	c.client = *clientset

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func (c *nameDotComDNSProviderSolver) loadConfig(cfgJSON *extapi.JSON) (*nameDotComDNSProviderConfig, error) {
	klog.Infof("Presenting configuration %+v", cfgJSON)
	cfg := nameDotComDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {

		klog.Error("configuration must be provided")
		return nil, errors.New("configuration must be provided")
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {

		klog.Error("error decoding solver config: %v", err.Error())
		return nil, fmt.Errorf("error decoding solver config: %v", err)
	}

	klog.Infof("Configuration parsed in %+v", cfg)
	if (cfg.UserName == nil || cfg.Token == nil || cfg.SecretRef != nil) &&
		(cfg.UserName != nil || cfg.Token == nil || cfg.SecretRef == nil) {

		klog.Error("either pair username/token or secretRef must be specified")
		return nil, errors.New("either pair username/token or secretRef must be specified")
	}

	if cfg.SecretRef != nil {

		secretNamespace := cfg.SecretRef.Namespace
		secretName := cfg.SecretRef.Name

		if secretNamespace == nil {
			*secretNamespace = "name-dot-com"
		}

		ctx, cancelFunct := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelFunct()
		secret, secretErr := c.client.CoreV1().Secrets(*secretNamespace).Get(ctx, *secretName, v1.GetOptions{})

		if secretErr != nil {
			return nil, secretErr
		}

		secretData := secret.Data

		if secretData["username"] == nil || secretData["token"] == nil {

			klog.Error("secret %s/%s not containing either username or token", *secretNamespace, *secretName)
			return nil, fmt.Errorf("secret %s/%s not containing either username or token", *secretNamespace, *secretName)
		}

		*cfg.UserName = string(secretData["username"])
		*cfg.Token = string(secretData["token"])

		select {
		case <-ctx.Done():

			return nil, ctx.Err()
		default:

		}
	}

	klog.Infof("Configuration for %s read", *cfg.UserName)

	return &cfg, nil
}

func extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+util.UnFqdn(domain)); idx != -1 {
		return name[:idx]
	}
	return name
}

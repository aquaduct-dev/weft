package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/rs/zerolog/log"
)

// UpdateRecord updates the DNS records for the given hostname to point to the target IP.
// It deletes all existing records for the hostname and creates a new A record.
// It also creates a TXT record indicating the update.
func UpdateRecord(token string, hostname string, targetIP string) error {
	api, err := cloudflare.NewWithAPIToken(token)
	if err != nil {
		return fmt.Errorf("failed to create cloudflare client: %w", err)
	}

	// We need to find the zone ID. Since hostname can be a subdomain, we search for the zone
	// that matches the hostname's domain.
	ctx := context.Background()
	zones, err := api.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("failed to list zones: %w", err)
	}

	var zoneID string
	var zoneName string
	maxLen := 0

	for _, z := range zones {
		if strings.HasSuffix(hostname, z.Name) {
			// Find the longest matching zone (e.g. for foo.bar.com, match bar.com over com)
			if len(z.Name) > maxLen {
				maxLen = len(z.Name)
				zoneID = z.ID
				zoneName = z.Name
			}
		}
	}

	if zoneID == "" {
		return fmt.Errorf("could not find zone for hostname %s", hostname)
	}

	log.Info().Str("hostname", hostname).Str("zone", zoneName).Msg("Found Cloudflare zone")

	// List existing records for the hostname
	records, _, err := api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
		Name: hostname,
	})
	if err != nil {
		return fmt.Errorf("failed to list DNS records: %w", err)
	}

	// Delete existing records
	for _, r := range records {
		log.Info().Str("record", r.Name).Str("type", r.Type).Msg("Deleting existing DNS record")
		if err := api.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), r.ID); err != nil {
			return fmt.Errorf("failed to delete record %s: %w", r.ID, err)
		}
	}

	// Create A record
	_, err = api.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.CreateDNSRecordParams{
		Type:    "A",
		Name:    hostname,
		Content: targetIP,
		Proxied: cloudflare.BoolPtr(false), // Grey cloud
		TTL:     120,                       // Short TTL
	})
	if err != nil {
		return fmt.Errorf("failed to create A record: %w", err)
	}

	// Create TXT record
	txtContent := fmt.Sprintf("Weft: updated %s at %s", targetIP, time.Now().Format(time.RFC3339))
	_, err = api.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.CreateDNSRecordParams{
		Type:    "TXT",
		Name:    hostname,
		Content: txtContent,
		TTL:     120,
	})
	if err != nil {
		return fmt.Errorf("failed to create TXT record: %w", err)
	}

	log.Info().Str("hostname", hostname).Str("ip", targetIP).Msg("Updated Cloudflare DNS records")
	return nil
}

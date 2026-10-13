package aws

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/accuknox/omniscan/pkg/resource"
)

func (p *Provider) ListVMs(ctx context.Context) ([]resource.VM, error) {
	input := &ec2.DescribeInstancesInput{}
	if !p.vmFilter.MultiAZ {
		host, err := p.imds.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
		if err != nil {
			return nil, fmt.Errorf("querying host instance identity: %w", err)
		}
		input.Filters = []types.Filter{
			{
				Name:   aws.String("availability-zone"),
				Values: []string{host.AvailabilityZone},
			},
		}
	}
	iter := ec2.NewDescribeInstancesPaginator(p.ec2, input)

	var vms []resource.VM

	for iter.HasMorePages() {
		page, err := iter.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("querying next page: %w", err)
		}
		for _, reservation := range page.Reservations {
			for _, i := range reservation.Instances {
				if i.State == nil || i.State.Name != types.InstanceStateNameRunning {
					continue
				}

				if i.InstanceId == nil {
					continue
				}
				instanceID := *i.InstanceId

				name := resourceNameFromTags(i.Tags)
				if r := p.vmFilter.Name; r != nil && !r.MatchString(name) {
					p.logger.LogAttrs(
						ctx,
						slog.LevelDebug,
						"instance name did not match the provided filter. Skipping...",
						slog.String("vm_uri", instanceID),
						slog.String("vm_name", name),
					)
					continue
				}

				var match bool

			NextLabel:
				for _, t := range i.Tags {
					var k, v string
					if t.Key != nil {
						k = *t.Key
					}
					if t.Value != nil {
						v = *t.Value
					}
					if k == "" && v == "" {
						continue
					}
					for _, r := range p.vmFilter.Labels {
						if r.Key != nil && !r.Key.MatchString(k) {
							continue
						}
						if r.Value != nil && !r.Value.MatchString(v) {
							continue
						}
						match = true
						break NextLabel
					}
				}

				if !match && len(p.vmFilter.Labels) != 0 {
					p.logger.LogAttrs(
						ctx,
						slog.LevelDebug,
						"vm labels did not match the provided filter. Skipping...",
						slog.String("vm_uri", instanceID),
						slog.Any("vm_labels", i.Tags),
					)
					continue
				}

				volumes, err := p.ec2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
					Filters: []types.Filter{
						{
							Name:   aws.String("attachment.instance-id"),
							Values: []string{instanceID},
						},
					},
				})
				if err != nil {
					return nil, fmt.Errorf("listing volumes attached to %q: %w", instanceID, err)
				}

				var disks []resource.Disk
				var rootDiskURI string

				for _, vol := range volumes.Volumes {
					if vol.State != types.VolumeStateInUse {
						continue
					}
					for _, attachement := range vol.Attachments {
						if attachement.InstanceId == nil || attachement.Device == nil {
							continue
						}
						if *attachement.InstanceId != instanceID {
							continue
						}
						if isRootDevice(*attachement.Device) {
							rootDiskURI = *vol.VolumeId
						}
					}
					disks = append(disks, resource.Disk{
						URI: *vol.VolumeId,
					})
				}

				if rootDiskURI == "" {
					p.logger.LogAttrs(
						ctx,
						slog.LevelWarn,
						"root disk not found. Skipping...",
						slog.String("vm_uri", p.buildInstanceARN(instanceID)),
					)
					continue
				}

				slices.SortFunc(disks, func(a, b resource.Disk) int {
					if a.URI == rootDiskURI {
						return -1
					}
					if b.URI == rootDiskURI {
						return 1
					}
					return 0
				})

				vms = append(vms, resource.VM{
					URI:   p.buildInstanceARN(instanceID),
					Disks: disks,
				})
			}
		}
	}

	return vms, nil
}

func (p *Provider) GetCurrentVM(ctx context.Context) (*resource.VM, error) {
	host, err := p.imds.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		return nil, fmt.Errorf("querying host instance identity: %w", err)
	}

	volumes, err := p.ec2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("attachment.instance-id"),
				Values: []string{host.InstanceID},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("querying volumes attached to host: %w", err)
	}

	var disks []resource.Disk
	var rootDiskURI string

	for _, vol := range volumes.Volumes {
		if vol.State != types.VolumeStateInUse {
			continue
		}
		for _, attachement := range vol.Attachments {
			if attachement.InstanceId == nil || attachement.Device == nil {
				continue
			}
			if *attachement.InstanceId != host.InstanceID {
				continue
			}
			if isRootDevice(*attachement.Device) {
				rootDiskURI = *vol.VolumeId
			}
		}
		disks = append(disks, resource.Disk{
			URI: *vol.VolumeId,
		})
	}

	if rootDiskURI == "" {
		return nil, fmt.Errorf("root disk not found")
	}

	slices.SortFunc(disks, func(a, b resource.Disk) int {
		if a.URI == rootDiskURI {
			return -1
		}
		if b.URI == rootDiskURI {
			return 1
		}
		return 0
	})

	return &resource.VM{
		URI:   p.buildInstanceARN(host.InstanceID),
		Disks: disks,
	}, nil
}

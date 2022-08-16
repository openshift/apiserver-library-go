// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	imagev1 "github.com/openshift/api/image/v1"
	applyconfigurationsimagev1 "github.com/openshift/client-go/image/applyconfigurations/image/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeImageStreams implements ImageStreamInterface
type FakeImageStreams struct {
	Fake *FakeImageV1
	ns   string
}

var imagestreamsResource = schema.GroupVersionResource{Group: "image.openshift.io", Version: "v1", Resource: "imagestreams"}

var imagestreamsKind = schema.GroupVersionKind{Group: "image.openshift.io", Version: "v1", Kind: "ImageStream"}

// Get takes name of the imageStream, and returns the corresponding imageStream object, and an error if there is any.
func (c *FakeImageStreams) Get(ctx context.Context, name string, options v1.GetOptions) (result *imagev1.ImageStream, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(imagestreamsResource, c.ns, name), &imagev1.ImageStream{})

	if obj == nil {
		return nil, err
	}
	return obj.(*imagev1.ImageStream), err
}

// List takes label and field selectors, and returns the list of ImageStreams that match those selectors.
func (c *FakeImageStreams) List(ctx context.Context, opts v1.ListOptions) (result *imagev1.ImageStreamList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(imagestreamsResource, imagestreamsKind, c.ns, opts), &imagev1.ImageStreamList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &imagev1.ImageStreamList{ListMeta: obj.(*imagev1.ImageStreamList).ListMeta}
	for _, item := range obj.(*imagev1.ImageStreamList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested imageStreams.
func (c *FakeImageStreams) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(imagestreamsResource, c.ns, opts))

}

// Create takes the representation of a imageStream and creates it.  Returns the server's representation of the imageStream, and an error, if there is any.
func (c *FakeImageStreams) Create(ctx context.Context, imageStream *imagev1.ImageStream, opts v1.CreateOptions) (result *imagev1.ImageStream, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(imagestreamsResource, c.ns, imageStream), &imagev1.ImageStream{})

	if obj == nil {
		return nil, err
	}
	return obj.(*imagev1.ImageStream), err
}

// Update takes the representation of a imageStream and updates it. Returns the server's representation of the imageStream, and an error, if there is any.
func (c *FakeImageStreams) Update(ctx context.Context, imageStream *imagev1.ImageStream, opts v1.UpdateOptions) (result *imagev1.ImageStream, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(imagestreamsResource, c.ns, imageStream), &imagev1.ImageStream{})

	if obj == nil {
		return nil, err
	}
	return obj.(*imagev1.ImageStream), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeImageStreams) UpdateStatus(ctx context.Context, imageStream *imagev1.ImageStream, opts v1.UpdateOptions) (*imagev1.ImageStream, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(imagestreamsResource, "status", c.ns, imageStream), &imagev1.ImageStream{})

	if obj == nil {
		return nil, err
	}
	return obj.(*imagev1.ImageStream), err
}

// Delete takes name of the imageStream and deletes it. Returns an error if one occurs.
func (c *FakeImageStreams) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(imagestreamsResource, c.ns, name, opts), &imagev1.ImageStream{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeImageStreams) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(imagestreamsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &imagev1.ImageStreamList{})
	return err
}

// Patch applies the patch and returns the patched imageStream.
func (c *FakeImageStreams) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *imagev1.ImageStream, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(imagestreamsResource, c.ns, name, pt, data, subresources...), &imagev1.ImageStream{})

	if obj == nil {
		return nil, err
	}
	return obj.(*imagev1.ImageStream), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied imageStream.
func (c *FakeImageStreams) Apply(ctx context.Context, imageStream *applyconfigurationsimagev1.ImageStreamApplyConfiguration, opts v1.ApplyOptions) (result *imagev1.ImageStream, err error) {
	if imageStream == nil {
		return nil, fmt.Errorf("imageStream provided to Apply must not be nil")
	}
	data, err := json.Marshal(imageStream)
	if err != nil {
		return nil, err
	}
	name := imageStream.Name
	if name == nil {
		return nil, fmt.Errorf("imageStream.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(imagestreamsResource, c.ns, *name, types.ApplyPatchType, data), &imagev1.ImageStream{})

	if obj == nil {
		return nil, err
	}
	return obj.(*imagev1.ImageStream), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeImageStreams) ApplyStatus(ctx context.Context, imageStream *applyconfigurationsimagev1.ImageStreamApplyConfiguration, opts v1.ApplyOptions) (result *imagev1.ImageStream, err error) {
	if imageStream == nil {
		return nil, fmt.Errorf("imageStream provided to Apply must not be nil")
	}
	data, err := json.Marshal(imageStream)
	if err != nil {
		return nil, err
	}
	name := imageStream.Name
	if name == nil {
		return nil, fmt.Errorf("imageStream.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(imagestreamsResource, c.ns, *name, types.ApplyPatchType, data, "status"), &imagev1.ImageStream{})

	if obj == nil {
		return nil, err
	}
	return obj.(*imagev1.ImageStream), err
}

// Secrets takes name of the imageStream, and returns the corresponding secretList object, and an error if there is any.
func (c *FakeImageStreams) Secrets(ctx context.Context, imageStreamName string, options v1.GetOptions) (result *imagev1.SecretList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetSubresourceAction(imagestreamsResource, c.ns, "secrets", imageStreamName), &imagev1.SecretList{})

	if obj == nil {
		return nil, err
	}
	return obj.(*imagev1.SecretList), err
}

// Layers takes name of the imageStream, and returns the corresponding imageStreamLayers object, and an error if there is any.
func (c *FakeImageStreams) Layers(ctx context.Context, imageStreamName string, options v1.GetOptions) (result *imagev1.ImageStreamLayers, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetSubresourceAction(imagestreamsResource, c.ns, "layers", imageStreamName), &imagev1.ImageStreamLayers{})

	if obj == nil {
		return nil, err
	}
	return obj.(*imagev1.ImageStreamLayers), err
}

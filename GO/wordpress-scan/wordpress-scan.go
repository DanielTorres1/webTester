package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

type Route struct {
	Name string
	Path string
}

var routes = []Route{
	{"loginizer", "wp-content/plugins/loginizer/"},
	{"wp-file-manager", "wp-content/plugins/wp-file-manager/"},
	{"wp-statistics", "wp-content/plugins/wp-statistics/"},
	{"woocommerce-abandoned-cart", "wp-content/plugins/woocommerce-abandoned-cart/"},
	{"404-to-301", "wp-content/plugins/404-to-301/"},
	{"adrotate", "wp-content/plugins/adrotate/"},
	{"advanced-access-manager", "wp-content/plugins/advanced-access-manager/"},
	{"advanced-cf7-db", "wp-content/plugins/advanced-cf7-db/"},
	{"affiliates-manager", "wp-content/plugins/affiliates-manager/"},
	{"ajax-load-more", "wp-content/plugins/ajax-load-more/"},
	{"ajax-search-lite", "wp-content/plugins/ajax-search-lite/"},
	{"all-in-one-event-calendar", "wp-content/plugins/all-in-one-event-calendar/"},
	{"asgaros-forum", "wp-content/plugins/asgaros-forum/"},
	{"backupwordpress", "wp-content/plugins/backupwordpress/"},
	{"backwpup", "wp-content/plugins/backwpup/"},
	{"bbpress", "wp-content/plugins/bbpress/"},
	{"bj-lazy-load", "wp-content/plugins/bj-lazy-load/"},
	{"blackhole-bad-bots", "wp-content/plugins/blackhole-bad-bots/"},
	{"blog2social", "wp-content/plugins/blog2social/"},
	{"bp-profile-search", "wp-content/plugins/bp-profile-search/"},
	{"bsk-pdf-manager", "wp-content/plugins/bsk-pdf-manager/"},
	{"buddypress", "wp-content/plugins/buddypress/"},
	{"buddypress-media", "wp-content/plugins/buddypress-media/"},
	{"calculated-fields-form", "wp-content/plugins/calculated-fields-form/"},
	{"capability-manager-enhanced", "wp-content/plugins/capability-manager-enhanced/"},
	{"companion-auto-update", "wp-content/plugins/companion-auto-update/"},
	{"contextual-related-posts", "wp-content/plugins/contextual-related-posts/"},
	{"controlled-admin-access", "wp-content/plugins/controlled-admin-access/"},
	{"custom-404-pro", "wp-content/plugins/custom-404-pro/"},
	{"custom-contact-forms", "wp-content/plugins/custom-contact-forms/"},
	{"custom-registration-form-builder-with-submission-manager", "wp-content/plugins/custom-registration-form-builder-with-submission-manager/"},
	{"disqus-comment-system", "wp-content/plugins/disqus-comment-system/"},
	{"dokan-lite", "wp-content/plugins/dokan-lite/"},
	{"download-manager", "wp-content/plugins/download-manager/"},
	{"download-monitor", "wp-content/plugins/download-monitor/"},
	{"drag-and-drop-multiple-file-upload-contact-form-7", "wp-content/plugins/drag-and-drop-multiple-file-upload-contact-form-7/"},
	{"easy-digital-downloads", "wp-content/plugins/easy-digital-downloads/"},
	{"easy-wp-smtp", "wp-content/plugins/easy-wp-smtp/"},
	{"ecwid-shopping-cart", "wp-content/plugins/ecwid-shopping-cart/"},
	{"email-before-download", "wp-content/plugins/email-before-download/"},
	{"email-subscribers", "wp-content/plugins/email-subscribers/"},
	{"events-manager", "wp-content/plugins/events-manager/"},
	{"everest-forms", "wp-content/plugins/everest-forms/"},
	{"ezoic-integration", "wp-content/plugins/ezoic-integration/"},
	{"feed-them-social", "wp-content/plugins/feed-them-social"},
	{"flickr-gallery", "wp-content/plugins/flickr-gallery/"},
	{"formidable", "wp-content/plugins/formidable/"},
	{"form-maker", "wp-content/plugins/form-maker/"},
	{"ga-google-analytics", "wp-content/plugins/ga-google-analytics/"},
	{"google-captcha", "wp-content/plugins/google-captcha/"},
	{"google-sitemap-generator", "wp-content/plugins/google-sitemap-generator/"},
	{"gravityforms", "wp-content/plugins/gravityforms/"},
	{"imagify", "wp-content/plugins/imagify/"},
	{"instagram-feed", "wp-content/plugins/instagram-feed/"},
	{"intense", "wp-content/plugins/intense/"},
	{"ithemes-security-pro", "wp-content/plugins/ithemes-security-pro/"},
	{"jetpack", "wp-content/plugins/jetpack/"},
	{"js_composer", "wp-content/plugins/js_composer/"},
	{"layerslider", "wp-content/plugins/layerslider/"},
	{"lazy-load", "wp-content/plugins/lazy-load/"},
	{"mainwp-child", "wp-content/plugins/mainwp-child/"},
	{"mailchimp-for-wp", "wp-content/plugins/mailchimp-for-wp/"},
	{"mailpoet", "wp-content/plugins/mailpoet/"},
	{"media-element-html5-video-and-audio-player", "wp-content/plugins/media-element-html5-video-and-audio-player/"},
	{"meta-box", "wp-content/plugins/meta-box/"},
	{"monarch", "wp-content/plugins/monarch/"},
	{"ninja-forms", "wp-content/plugins/ninja-forms/"},
	{"osm", "wp-content/plugins/osm/"},
	{"page-links-to", "wp-content/plugins/page-links-to/"},
	{"paid-memberships-pro", "wp-content/plugins/paid-memberships-pro/"},
	{"popup-maker", "wp-content/plugins/popup-maker/"},
	{"profile-builder", "wp-content/plugins/profile-builder/"},
	{"really-simple-captcha", "wp-content/plugins/really-simple-captcha/"},
	{"regenerate-thumbnails", "wp-content/plugins/regenerate-thumbnails/"},
	{"related-posts-thumbnails", "wp-content/plugins/related-posts-thumbnails/"},
	{"revslider", "wp-content/plugins/revslider/"},
	{"rw-real-media-library", "wp-content/plugins/rw-real-media-library/"},
	{"simple-download-monitor", "wp-content/plugins/simple-download-monitor/"},
	{"siteorigin-panels", "wp-content/plugins/siteorigin-panels/"},
	{"slideshow-jquery-image-gallery", "wp-content/plugins/slideshow-jquery-image-gallery/"},
	{"smush", "wp-content/plugins/smush/"},
	{"snapchat-for-wp", "wp-content/plugins/snapchat-for-wp/"},
	{"social-icons", "wp-content/plugins/social-icons/"},
	{"subscribe-to-comments-reloaded", "wp-content/plugins/subscribe-to-comments-reloaded/"},
	{"sucuri-scanner", "wp-content/plugins/sucuri-scanner/"},
	{"tablepress", "wp-content/plugins/tablepress/"},
	{"the-events-calendar", "wp-content/plugins/the-events-calendar/"},
	{"tinymce-advanced", "wp-content/plugins/tinymce-advanced/"},
	{"user-registration", "wp-content/plugins/user-registration/"},
	{"users-ultra", "wp-content/plugins/users-ultra/"},
	{"w3-total-cache", "wp-content/plugins/w3-total-cache/"},
	{"woocommerce", "wp-content/plugins/woocommerce/"},
	{"wordfence", "wp-content/plugins/wordfence/"},
	{"wordpress-importer", "wp-content/plugins/wordpress-importer/"},
	{"wordpress-seo", "wp-content/plugins/wordpress-seo/"},
	{"wp-fastest-cache", "wp-content/plugins/wp-fastest-cache/"},
	{"wp-file-manager", "wp-content/plugins/wp-file-manager/"},
	{"wpforms-lite", "wp-content/plugins/wpforms-lite/"},
	{"wp-google-maps", "wp-content/plugins/wp-google-maps/"},
	{"wp-mail-smtp", "wp-content/plugins/wp-mail-smtp/"},
	{"wp-migrate-db", "wp-content/plugins/wp-migrate-db/"},
	{"wp-pagenavi", "wp-content/plugins/wp-pagenavi/"},
	{"wp-super-cache", "wp-content/plugins/wp-super-cache/"},
	{"wp-sweep", "wp-content/plugins/wp-sweep/"},
	{"wp-user-avatar", "wp-content/plugins/wp-user-avatar/"},
	{"yith-woocommerce-compare", "wp-content/plugins/yith-woocommerce-compare/"},
	{"yith-woocommerce-wishlist", "wp-content/plugins/yith-woocommerce-wishlist/"},
}

func main() {
	url := flag.String("url", "", "URL to check")
	flag.Parse()

	if *url == "" {
		fmt.Println("Usage: go run script.go -url=<url>")
		os.Exit(1)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: time.Duration(10 * time.Second)}

	fmt.Println("Nombre | Status Code | Resultado")
	for _, route := range routes {
		resp, err := client.Head(*url + route.Path)
		if err != nil {
			fmt.Printf("%s | Error | %v\n", route.Name, err)
			continue
		}
		defer resp.Body.Close()

		result := "OK"
		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			result = "Vulnerable"
		}

		fmt.Printf("%s | %d | %s\n", route.Name, resp.StatusCode, result)
	}
}

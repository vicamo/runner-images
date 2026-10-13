source "lxd" "image" {
  image        = local.source_image
  output_image = var.image_os

  launch_config = {
    "security.nesting" = "true"
  }

  publish_properties = {
    description = "GitHub Actions runner image ${var.image_os} ${var.image_version}"
  }
}

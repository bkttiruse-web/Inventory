# Video Background Setup

## To add an animated background to the login page:

### 1. Create or obtain a video file
- Create your own looping animation in Blender, After Effects, or similar
- Or use a royalty-free stock video
- **Important**: Ensure you have rights to use any video in your project

### 2. Optimize the video
- **Recommended format**: WebM (better compression, smaller file size)
- **Fallback format**: MP4 (wider compatibility)
- **Recommended resolution**: 1920x1080 or 1280x720
- **Keep file size under 5MB** for fast loading
- **Duration**: 10-20 seconds looping seamlessly

### 3. Add video files to this directory
```
public/
├── videos/
│   ├── beams.webm   (preferred)
│   └── beams.mp4    (fallback)
```

### 4. Uncomment the video tag in index.html
Look for this section and remove the comment tags:
```html
<!-- <video class="background-video" autoplay muted loop playsinline>
  <source src="/videos/beams.webm" type="video/webm">
  <source src="/videos/beams.mp4" type="video/mp4">
</video> -->
```

Should become:
```html
<video class="background-video" autoplay muted loop playsinline>
  <source src="/videos/beams.webm" type="video/webm">
  <source src="/videos/beams.mp4" type="video/mp4">
</video>
```

### 5. Video conversion tools
If you need to convert your video:
- **Online**: CloudConvert.com, Online-Convert.com
- **Software**: FFmpeg, HandBrake
- **FFmpeg command** for WebM:
  ```bash
  ffmpeg -i input.mp4 -c:v libvpx-vp9 -b:v 1M -c:a libopus -b:a 64k output.webm
  ```

## Current Setup
The login page currently shows a purple gradient background as a fallback. This looks professional and loads instantly while you work on getting the perfect video.

// Vanilla Three.js Beams Animation
// Converted from React Three Fiber component

class BeamsAnimation {
  constructor(containerId, options = {}) {
    this.container = document.getElementById(containerId);
    if (!this.container) {
      console.error(`Container ${containerId} not found`);
      return;
    }

    // Configuration
    this.config = {
      beamWidth: options.beamWidth || 2,
      beamHeight: options.beamHeight || 15,
      beamNumber: options.beamNumber || 12,
      lightColor: options.lightColor || '#A7D8FF',
      speed: options.speed || 2,
      noiseIntensity: options.noiseIntensity || 1.75,
      scale: options.scale || 0.2,
      rotation: options.rotation || 0,
      backgroundColor: options.backgroundColor || '#A7D8FF'
    };

    this.time = 0;
    this.init();
  }

  init() {
    // Scene setup
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(this.config.backgroundColor);

    // Camera setup
    this.camera = new THREE.PerspectiveCamera(
      30,
      this.container.clientWidth / this.container.clientHeight,
      0.1,
      1000
    );
    this.camera.position.set(0, 0, 20);

    // Renderer setup
    this.renderer = new THREE.WebGLRenderer({ antialias: true });
    this.renderer.setSize(this.container.clientWidth, this.container.clientHeight);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.container.appendChild(this.renderer.domElement);

    // Lights
    this.ambientLight = new THREE.AmbientLight(0xffffff, 1);
    this.scene.add(this.ambientLight);

    const dirLight = new THREE.DirectionalLight(this.config.lightColor, 1);
    dirLight.position.set(0, 3, 10);
    this.scene.add(dirLight);

    // Create beams group
    this.beamsGroup = new THREE.Group();
    this.beamsGroup.rotation.z = THREE.MathUtils.degToRad(this.config.rotation);
    this.scene.add(this.beamsGroup);

    // Create beam material
    this.createBeamMaterial();

    // Create beam meshes
    this.createBeams();

    // Handle window resize
    window.addEventListener('resize', () => this.onWindowResize());

    // Start animation
    this.animate();
  }

  createBeamMaterial() {
    // Noise shader functions
    const noiseShader = `
      float random (in vec2 st) {
        return fract(sin(dot(st.xy, vec2(12.9898,78.233))) * 43758.5453123);
      }

      float noise (in vec2 st) {
        vec2 i = floor(st);
        vec2 f = fract(st);
        float a = random(i);
        float b = random(i + vec2(1.0, 0.0));
        float c = random(i + vec2(0.0, 1.0));
        float d = random(i + vec2(1.0, 1.0));
        vec2 u = f * f * (3.0 - 2.0 * f);
        return mix(a, b, u.x) + (c - a) * u.y * (1.0 - u.x) + (d - b) * u.x * u.y;
      }

      vec4 permute(vec4 x) { return mod(((x*34.0)+1.0)*x, 289.0); }
      vec4 taylorInvSqrt(vec4 r) { return 1.79284291400159 - 0.85373472095314 * r; }
      vec3 fade(vec3 t) { return t*t*t*(t*(t*6.0-15.0)+10.0); }

      float cnoise(vec3 P) {
        vec3 Pi0 = floor(P);
        vec3 Pi1 = Pi0 + vec3(1.0);
        Pi0 = mod(Pi0, 289.0);
        Pi1 = mod(Pi1, 289.0);
        vec3 Pf0 = fract(P);
        vec3 Pf1 = Pf0 - vec3(1.0);
        vec4 ix = vec4(Pi0.x, Pi1.x, Pi0.x, Pi1.x);
        vec4 iy = vec4(Pi0.yy, Pi1.yy);
        vec4 iz0 = Pi0.zzzz;
        vec4 iz1 = Pi1.zzzz;
        vec4 ixy = permute(permute(ix) + iy);
        vec4 ixy0 = permute(ixy + iz0);
        vec4 ixy1 = permute(ixy + iz1);
        vec4 gx0 = ixy0 / 7.0;
        vec4 gy0 = fract(floor(gx0) / 7.0) - 0.5;
        gx0 = fract(gx0);
        vec4 gz0 = vec4(0.5) - abs(gx0) - abs(gy0);
        vec4 sz0 = step(gz0, vec4(0.0));
        gx0 -= sz0 * (step(0.0, gx0) - 0.5);
        gy0 -= sz0 * (step(0.0, gy0) - 0.5);
        vec4 gx1 = ixy1 / 7.0;
        vec4 gy1 = fract(floor(gx1) / 7.0) - 0.5;
        gx1 = fract(gx1);
        vec4 gz1 = vec4(0.5) - abs(gx1) - abs(gy1);
        vec4 sz1 = step(gz1, vec4(0.0));
        gx1 -= sz1 * (step(0.0, gx1) - 0.5);
        gy1 -= sz1 * (step(0.0, gy1) - 0.5);
        vec3 g000 = vec3(gx0.x,gy0.x,gz0.x);
        vec3 g100 = vec3(gx0.y,gy0.y,gz0.y);
        vec3 g010 = vec3(gx0.z,gy0.z,gz0.z);
        vec3 g110 = vec3(gx0.w,gy0.w,gz0.w);
        vec3 g001 = vec3(gx1.x,gy1.x,gz1.x);
        vec3 g101 = vec3(gx1.y,gy1.y,gz1.y);
        vec3 g011 = vec3(gx1.z,gy1.z,gz1.z);
        vec3 g111 = vec3(gx1.w,gy1.w,gz1.w);
        vec4 norm0 = taylorInvSqrt(vec4(dot(g000,g000),dot(g010,g010),dot(g100,g100),dot(g110,g110)));
        g000 *= norm0.x; g010 *= norm0.y; g100 *= norm0.z; g110 *= norm0.w;
        vec4 norm1 = taylorInvSqrt(vec4(dot(g001,g001),dot(g011,g011),dot(g101,g101),dot(g111,g111)));
        g001 *= norm1.x; g011 *= norm1.y; g101 *= norm1.z; g111 *= norm1.w;
        float n000 = dot(g000, Pf0);
        float n100 = dot(g100, vec3(Pf1.x,Pf0.yz));
        float n010 = dot(g010, vec3(Pf0.x,Pf1.y,Pf0.z));
        float n110 = dot(g110, vec3(Pf1.xy,Pf0.z));
        float n001 = dot(g001, vec3(Pf0.xy,Pf1.z));
        float n101 = dot(g101, vec3(Pf1.x,Pf0.y,Pf1.z));
        float n011 = dot(g011, vec3(Pf0.x,Pf1.yz));
        float n111 = dot(g111, Pf1);
        vec3 fade_xyz = fade(Pf0);
        vec4 n_z = mix(vec4(n000,n100,n010,n110),vec4(n001,n101,n011,n111),fade_xyz.z);
        vec2 n_yz = mix(n_z.xy,n_z.zw,fade_xyz.y);
        float n_xyz = mix(n_yz.x,n_yz.y,fade_xyz.x);
        return 2.2 * n_xyz;
      }
    `;

    const vertexShader = `
      varying vec2 vUv;
      varying vec3 vPosition;
      uniform float time;
      uniform float uSpeed;
      uniform float uScale;

      ${noiseShader}

      float getPos(vec3 pos) {
        vec3 noisePos = vec3(pos.x * 0.0, pos.y - vUv.y, pos.z + time * uSpeed * 3.0) * uScale;
        return cnoise(noisePos);
      }

      void main() {
        vUv = uv;
        vPosition = position;
        
        vec3 transformed = position;
        transformed.z += getPos(transformed);
        
        gl_Position = projectionMatrix * modelViewMatrix * vec4(transformed, 1.0);
      }
    `;

    const fragmentShader = `
      varying vec2 vUv;
      varying vec3 vPosition;
      uniform float time;
      uniform float uNoiseIntensity;
      uniform vec3 color;

      ${noiseShader}

      void main() {
        float randomNoise = noise(gl_FragCoord.xy);
        vec3 finalColor = color - randomNoise / 15.0 * uNoiseIntensity;
        gl_FragColor = vec4(finalColor, 1.0);
      }
    `;

    this.beamMaterial = new THREE.ShaderMaterial({
      uniforms: {
        time: { value: 0 },
        uSpeed: { value: this.config.speed },
        uScale: { value: this.config.scale },
        uNoiseIntensity: { value: this.config.noiseIntensity },
        color: { value: new THREE.Color('#FFD6A5') }
      },
      vertexShader: vertexShader,
      fragmentShader: fragmentShader,
      side: THREE.DoubleSide
    });
  }

  createBeams() {
    const geometry = new THREE.PlaneGeometry(
      this.config.beamWidth,
      this.config.beamHeight,
      32,
      32
    );

    const angleStep = (Math.PI * 2) / this.config.beamNumber;
    const radius = 8;

    for (let i = 0; i < this.config.beamNumber; i++) {
      const mesh = new THREE.Mesh(geometry, this.beamMaterial);
      const angle = i * angleStep;
      
      mesh.position.x = Math.cos(angle) * radius;
      mesh.position.y = Math.sin(angle) * radius;
      mesh.rotation.z = angle + Math.PI / 2;
      
      this.beamsGroup.add(mesh);
    }
  }

  animate() {
    requestAnimationFrame(() => this.animate());

    this.time += 0.01;
    this.beamMaterial.uniforms.time.value = this.time;

    this.renderer.render(this.scene, this.camera);
  }

  onWindowResize() {
    if (!this.container || !this.renderer || !this.camera) return;
    
    const width = Math.max(window.innerWidth, this.container.clientWidth);
    const height = Math.max(window.innerHeight, this.container.clientHeight);

    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();

    this.renderer.setSize(width, height);
    
    // Ensure canvas fills the container
    if (this.renderer.domElement) {
      this.renderer.domElement.style.width = '100%';
      this.renderer.domElement.style.height = '100%';
    }
  }

  destroy() {
    window.removeEventListener('resize', () => this.onWindowResize());
    this.container.removeChild(this.renderer.domElement);
    this.renderer.dispose();
  }
}

// Export for use in other scripts
window.BeamsAnimation = BeamsAnimation;

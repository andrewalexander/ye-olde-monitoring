# tilt up: same stack as docker-compose.yml, rebuilt when Go code changes.
docker_compose('./docker-compose.yml')

dc_resource('dnscount', labels=['dnscount'], links=[link('http://localhost:8081/api/health', 'admin health')])
dc_resource('caddy-log', labels=['dnscount'])
dc_resource('explore', labels=['dnscount'], links=[link('http://localhost:8090', 'explorer')])
dc_resource('caddy', labels=['web'], links=[link('http://localhost:8000', 'test page'), link('http://localhost:8002', 'caddy-site')])
dc_resource('app', labels=['web'], links=[link('http://localhost:8001', 'example app')])

local_resource('smoke', 'sh scripts/smoke.sh', resource_deps=['dnscount', 'caddy', 'caddy-log', 'explore', 'app'],
               auto_init=False, trigger_mode=TRIGGER_MODE_MANUAL, labels=['checks'])

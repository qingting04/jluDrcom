'use strict';

'require view';
'require form';
'require uci';
'require rpc';
'require poll';
'require ui';
'require tools.widgets as widgets';

var callStatus = rpc.declare({
	object: 'drcom',
	method: 'status',
	expect: { '': {} }
});

var callReconnect = rpc.declare({
	object: 'drcom',
	method: 'reconnect',
	expect: { '': {} }
});

var callReload = rpc.declare({
	object: 'drcom',
	method: 'reload',
	params: [ 'force' ],
	expect: { '': {} }
});

var callNetworkReload = rpc.declare({
	object: 'network',
	method: 'reload',
	expect: { '': {} }
});

var callInitAction = rpc.declare({
	object: 'luci',
	method: 'setInitAction',
	params: [ 'name', 'action' ],
	expect: { result: false }
});

function renderStatusBox(initial) {
	var state = (initial && initial.state) ? initial.state : '-';
	var lastErr = (initial && initial.last_error) ? initial.last_error : '';

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, [ _('状态') ]),
		E('div', { 'class': 'table', 'id': 'drcom-status-table' }, [
			E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td left' }, [ _('连接状态') ]),
				E('div', { 'class': 'td left', 'id': 'drcom-status-state' }, [ state ])
			]),
			E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td left' }, [ _('最近错误') ]),
				E('div', { 'class': 'td left', 'id': 'drcom-status-err' }, [ lastErr || '-' ])
			])
		])
	]);
}

function updateStatusBox(res) {
	var set = function(id, val) {
		var el = document.getElementById(id);
		if (el)
			el.textContent = val;
	};

	var stateMap = {
		'idle': _('空闲'),
		'online': _('已在线'),
		'challenge': _('获取挑战中'),
		'login': _('登录中'),
		'keepalive': _('保持在线')
	};
	var st = (res && res.state) ? res.state : '-';
	set('drcom-status-state', stateMap[st] || st);

	var le = (res && res.last_error) ? res.last_error : '-';
	if (le === 'manual reconnect')
		le = _('手动重连');
	set('drcom-status-err', le);
}

return view.extend({
	handleOneClick: function(m, ev) {
		return m.save().then(function() {
			var ifname = uci.get('drcom', 'main', 'interface');
			var ip = uci.get('drcom', 'main', 'ip');
			var mac = uci.get('drcom', 'main', 'mac');
			var gw = uci.get('drcom', 'main', 'gateway');

			if (!ifname)
				throw new Error(_('必须选择接口'));
			if (!ip)
				throw new Error(_('必须填写 IP 地址'));
			if (!mac)
				throw new Error(_('必须填写 MAC 地址'));
			if (!gw)
				throw new Error(_('必须填写网关'));

			mac = String(mac).toLowerCase();

			return Promise.all([ uci.load('network'), uci.load('dhcp') ]).then(function() {
				if (!uci.get('network', ifname))
					throw new Error(_('未找到网络接口“%s”').format(ifname));

				var dnsmasq = uci.sections('dhcp', 'dnsmasq');
				var dnsmasqSid = (dnsmasq && dnsmasq.length) ? dnsmasq[0]['.name'] : null;
				if (!dnsmasqSid)
					dnsmasqSid = uci.add('dhcp', 'dnsmasq');

				var oldProto = uci.get('network', ifname, 'proto');
				var oldIpaddr = uci.get('network', ifname, 'ipaddr');
				var oldNetmask = uci.get('network', ifname, 'netmask');
				var oldGateway = uci.get('network', ifname, 'gateway');
				var oldDns = uci.get('network', ifname, 'dns');
				var oldMacaddr = uci.get('network', ifname, 'macaddr');
				var oldRebind = uci.get('dhcp', dnsmasqSid, 'rebind_protection');

				uci.set('drcom', 'main', 'backup_ifname', ifname);
				uci.set('drcom', 'main', 'backup_proto', oldProto || '');
				uci.set('drcom', 'main', 'backup_ipaddr', oldIpaddr || '');
				uci.set('drcom', 'main', 'backup_netmask', oldNetmask || '');
				uci.set('drcom', 'main', 'backup_gateway', oldGateway || '');
				uci.set('drcom', 'main', 'backup_dns', oldDns || '');
				uci.set('drcom', 'main', 'backup_macaddr', oldMacaddr || '');
				uci.set('drcom', 'main', 'backup_rebind_protection', (oldRebind != null) ? String(oldRebind) : '');
				uci.set('drcom', 'main', 'backup_time', String(Date.now()));

				uci.set('network', ifname, 'proto', 'static');
				uci.set('network', ifname, 'ipaddr', ip);
				uci.set('network', ifname, 'macaddr', mac);
				uci.set('network', ifname, 'gateway', gw);
				uci.set('network', ifname, 'dns', [ '10.10.10.10', '202.98.18.3' ]);

				if (!uci.get('network', ifname, 'netmask'))
					uci.set('network', ifname, 'netmask', '255.255.255.0');

				uci.set('dhcp', dnsmasqSid, 'rebind_protection', '0');

				return uci.save();
			});
		}).then(function() {
			return Promise.all([
				callNetworkReload().catch(function(e) {
					ui.addNotification(null, E('p', [ _('网络重载失败：%s').format(String(e)) ]), 'warning');
				}),
				callInitAction('dnsmasq', 'restart').catch(function(e) {
					ui.addNotification(null, E('p', [ _('重启 dnsmasq 失败：%s').format(String(e)) ]), 'warning');
				})
			]);
		}).then(function() {
			ui.addNotification(null, E('p', [ _('一键配置已应用（静态 IP/MAC/网关/DNS + 关闭 DNS 重绑定保护）。') ]), 'info');
		}).catch(function(e) {
			ui.addNotification(null, E('p', [ String((e && e.message) ? e.message : e) ]), 'danger');
		});
	},

	handleRestore: function(m, ev) {
		ui.showModal(_('确认恢复设置？'), [
			E('p', [ _('这将恢复上次“一键配置”前备份的接口设置，并重新启用 DNS 重绑定保护。') ]),
			E('div', { 'class': 'right' }, [
				E('button', {
					'class': 'btn',
					'click': ui.createHandlerFn(this, ui.hideModal)
				}, [ _('取消') ]), ' ',
				E('button', {
					'class': 'btn cbi-button-action important',
					'click': ui.createHandlerFn(this, 'handleRestoreConfirm')
				}, [ _('继续') ])
			])
		]);
	},

	handleRestoreConfirm: function(ev) {
		ui.hideModal();

		return Promise.all([ uci.load('drcom'), uci.load('network'), uci.load('dhcp') ]).then(function() {
			var ifname = uci.get('drcom', 'main', 'backup_ifname');
			if (!ifname)
				throw new Error(_('未找到备份，请先执行“一键配置”。'));
			if (!uci.get('network', ifname))
				throw new Error(_('未找到网络接口“%s”').format(ifname));

			var setOrUnset = function(conf, sid, opt, val) {
				if (Array.isArray(val)) {
					if (!val.length)
						return uci.unset(conf, sid, opt);
					return uci.set(conf, sid, opt, val);
				}
				if (val == null || val === '')
					return uci.unset(conf, sid, opt);
				return uci.set(conf, sid, opt, val);
			};

			setOrUnset('network', ifname, 'proto', uci.get('drcom', 'main', 'backup_proto'));
			setOrUnset('network', ifname, 'ipaddr', uci.get('drcom', 'main', 'backup_ipaddr'));
			setOrUnset('network', ifname, 'netmask', uci.get('drcom', 'main', 'backup_netmask'));
			setOrUnset('network', ifname, 'gateway', uci.get('drcom', 'main', 'backup_gateway'));
			setOrUnset('network', ifname, 'dns', uci.get('drcom', 'main', 'backup_dns'));
			setOrUnset('network', ifname, 'macaddr', uci.get('drcom', 'main', 'backup_macaddr'));

			var dnsmasq = uci.sections('dhcp', 'dnsmasq');
			var dnsmasqSid = (dnsmasq && dnsmasq.length) ? dnsmasq[0]['.name'] : null;
			if (dnsmasqSid) {
				var rp = uci.get('drcom', 'main', 'backup_rebind_protection');
				uci.set('dhcp', dnsmasqSid, 'rebind_protection', (rp != null && rp !== '') ? rp : '1');
			}

			return uci.save();
		}).then(function() {
			return Promise.all([
				callNetworkReload().catch(function(e) {
					ui.addNotification(null, E('p', [ _('网络重载失败：%s').format(String(e)) ]), 'warning');
				}),
				callInitAction('dnsmasq', 'restart').catch(function(e) {
					ui.addNotification(null, E('p', [ _('重启 dnsmasq 失败：%s').format(String(e)) ]), 'warning');
				})
			]);
		}).then(function() {
			ui.addNotification(null, E('p', [ _('恢复已应用。') ]), 'info');
		}).catch(function(e) {
			ui.addNotification(null, E('p', [ String((e && e.message) ? e.message : e) ]), 'danger');
		});
	},

	load: function() {
		return Promise.all([
			uci.load('drcom'),
			callStatus().catch(function() { return {}; })
		]);
	},

	render: function(data) {
		var initialStatus = data[1] || {};

		var m = new form.Map('drcom', _('吉林大学 DrCOM'), _('吉林大学校园网 DrCOM 客户端守护进程。'));

		var s = m.section(form.NamedSection, 'main', 'drcom', _('设置'));
		s.addremove = false;

		var o;
		o = s.option(form.Flag, 'enabled', _('启用'));
		o.default = o.disabled;

		o = s.option(form.Value, 'username', _('账号'));
		o.datatype = 'string';

		o = s.option(form.Value, 'password', _('密码'));
		o.password = true;
		o.datatype = 'string';

		o = s.option(widgets.NetworkSelect, 'interface', _('接口'));
		o.nocreate = true;
		o.default = 'wan';
		o.rmempty = false;

		o = s.option(form.Value, 'ip', _('IP 地址'));
		o.datatype = 'ip4addr';
		o.placeholder = '10.100.61.100';
		o.rmempty = false;

		o = s.option(form.Value, 'gateway', _('网关'));
		o.datatype = 'ip4addr';
		o.placeholder = '10.100.61.1';
		o.rmempty = false;

		o = s.option(form.Value, 'mac', _('MAC 地址'));
		o.datatype = 'macaddr';
		o.placeholder = 'aa:bb:cc:dd:ee:ff';
		o.rmempty = false;

		return m.render().then(function(mapEl) {
			var statusBox = renderStatusBox(initialStatus);

			var actionsBox = E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('操作') ]),
				E('div', { 'class': 'cbi-section-actions' }, [
					E('button', {
						'class': 'cbi-button cbi-button-positive',
						'click': ui.createHandlerFn(this, function(ev) {
							var btn = ev.currentTarget;
							btn.disabled = true;
							return this.handleOneClick(m, ev).catch(function() {}).then(function() {
								btn.disabled = false;
							});
						})
					}, [ _('一键配置') ]),
					' ',
					E('button', {
						'class': 'cbi-button cbi-button-negative',
						'click': ui.createHandlerFn(this, function(ev) { return this.handleRestore(m, ev); })
					}, [ _('一键恢复') ]),
					' ',
					E('button', {
						'class': 'cbi-button cbi-button-action',
						'click': ui.createHandlerFn(this, function(ev) {
							var btn = ev.currentTarget;
							btn.disabled = true;
							return callReconnect().catch(function() {}).then(function() {
								btn.disabled = false;
							});
						})
					}, [ _('重连') ]),
					' ',
					E('button', {
						'class': 'cbi-button cbi-button-action',
						'click': ui.createHandlerFn(this, function(ev) {
							var btn = ev.currentTarget;
							btn.disabled = true;
							return callReload(true).catch(function() {}).then(function() {
								btn.disabled = false;
							});
						})
					}, [ _('重载配置') ])
				]),
				E('p', { 'class': 'cbi-section-descr' }, [ _('一键配置会将所选接口改为静态地址并伪装 MAC，写入网关与 DNS（10.10.10.10、202.98.18.3），并关闭 dnsmasq 的 DNS 重绑定保护；执行前会自动备份，便于一键恢复。') ])
			]);

			poll.add(function() {
				return callStatus().then(updateStatusBox).catch(function() {});
			});

			return E([], [ statusBox, actionsBox, mapEl ]);
		}.bind(this));
	}
});

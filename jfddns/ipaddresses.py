import ipaddress
from jfddns.validate import JfErr


def validate(address, ip_version=None):
    try:
        address = ipaddress.ip_address(address)
        if ip_version and ip_version != address.version:
            raise JfErr('IP version "{}" does not match.'.format(ip_version))
        return str(address), address.version
    except ValueError:
        raise JfErr('Invalid ip address "{}"'.format(address))


def format_attr(ip_version):
    return 'ipv{}'.format(ip_version)


class IpAddresses(object):

    def __init__(self, ip_1=None, ip_2=None, ipv4=None, ipv6=None):

        self.ipv4 = None
        """The ipv4 address to update DNS record with."""
        if ipv4:
            self.ipv4, ipv4_version = validate(ipv4, 4)

        self.ipv6 = None
        """The ipv6 address to update DNS record with."""
        if ipv6:
            self.ipv6, ipv6_version = validate(ipv6, 6)

        if ip_1:
            self._set_ip(ip_1)

        if ip_2:
            self._set_ip(ip_2)

        if not self.ipv4 and not self.ipv6:
            raise JfErr('No ip address set.')

    def _get_ip(self, ip_version):
        return getattr(self, format_attr(ip_version))

    def _setattr(self, ip_version, value):
        return setattr(self, format_attr(ip_version), value)

    def _set_ip(self, address):
        ip, ip_version = validate(address)
        old_ip = self._get_ip(ip_version)
        if old_ip:
            msg = 'The attribute "{}" is already set and has the value "{}"' \
                .format(
                    format_attr(ip_version),
                    old_ip,
                )
            raise JfErr(msg)

        self._set_attr(ip_version, ip)
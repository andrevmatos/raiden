import pytest

from raiden.constants import GAS_REQUIRED_FOR_DISCOVERY_REGISTER
from raiden.exceptions import UnknownAddress
from raiden.network.discovery import ContractDiscovery
from raiden.tests.utils.factories import make_address
from raiden.tests.utils.smartcontracts import deploy_contract_web3
from raiden.utils import host_port_to_endpoint, privatekey_to_address
from raiden_contracts.constants import CONTRACT_ENDPOINT_REGISTRY


@pytest.mark.parametrize('number_of_nodes', [1])
def test_endpointregistry(private_keys, blockchain_services, contract_manager):
    chain = blockchain_services.blockchain_services[0]
    my_address = privatekey_to_address(private_keys[0])

    endpointregistry_address = deploy_contract_web3(
        contract_name=CONTRACT_ENDPOINT_REGISTRY,
        deploy_client=chain.client,
        contract_manager=contract_manager,
        num_confirmations=None,
    )
    discovery_proxy = chain.discovery(endpointregistry_address)

    contract_discovery = ContractDiscovery(my_address, discovery_proxy)

    unregistered_address = make_address()

    # get should raise for unregistered addresses
    with pytest.raises(UnknownAddress):
        contract_discovery.get(my_address)

    with pytest.raises(UnknownAddress):
        contract_discovery.get(unregistered_address)

    contract_discovery.register(my_address, '127.0.0.1', 44444)
    assert contract_discovery.get(my_address) == ('127.0.0.1', 44444)

    contract_discovery.register(my_address, '127.0.0.1', 88888)
    assert contract_discovery.get(my_address) == ('127.0.0.1', 88888)

    with pytest.raises(UnknownAddress):
        contract_discovery.get(unregistered_address)


@pytest.mark.parametrize('number_of_nodes', [1])
def test_endpointregistry_gas(endpoint_discovery_services):
    """ GAS_REQUIRED_FOR_DISCOVERY_REGISTER value must be equal to the gas requried to call
    registerEndpoint.
    """
    contract_discovery = endpoint_discovery_services[0]
    discovery_proxy = contract_discovery.discovery_proxy
    endpoint = host_port_to_endpoint('127.0.0.1', 44444)

    transaction_hash = discovery_proxy.proxy.transact('registerEndpoint', endpoint)
    discovery_proxy.client.poll(transaction_hash)

    receipt = discovery_proxy.client.get_transaction_receipt(transaction_hash)
    assert receipt['gasUsed'] <= GAS_REQUIRED_FOR_DISCOVERY_REGISTER

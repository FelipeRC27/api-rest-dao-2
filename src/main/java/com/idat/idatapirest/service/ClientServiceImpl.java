package com.idat.idatapirest.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.idat.idatapirest.dto.ClienteRequestDTO;
import com.idat.idatapirest.dto.ClienteResponseDTO;
import com.idat.idatapirest.model.Clients;
import com.idat.idatapirest.repository.ClienteRepository;

@Service
public class ClientServiceImpl implements ClientService {

	@Autowired
	private ClienteRepository repository;
	
	@Override
	public void guardarCliente(ClienteRequestDTO p) {
		// TODO Auto-generated method stub
		Clients cliente = new Clients();
		cliente.setCelular(p.getCelularCliente());
		cliente.setCliente(p.getNombreCliente());
		cliente.setIdCliente(p.getIdCliente());
		repository.save(cliente);
	}

	@Override
	public void eliminarCliente(Integer id) {
		repository.deleteById(id);

	}

	@Override
	public void editarCliente(ClienteRequestDTO p) {
		// TODO Auto-generated method stub

	}

	@Override
	public List<ClienteResponseDTO> listarCliente() {

		List<Clients> cliente = repository.findAll();
		List<ClienteResponseDTO> dto = new ArrayList<ClienteResponseDTO>();
		ClienteResponseDTO clienteDTO = null;
		
		for (Clients c : cliente) {
			clienteDTO = new ClienteResponseDTO();
			clienteDTO.setIdCliente(c.getIdCliente());
			clienteDTO.setCelularCliente(c.getCelular());
			clienteDTO.setNombreCliente(c.getCliente());
			dto.add(clienteDTO);
		}
		
		return dto;
	}

	@Override
	public ClienteResponseDTO clienteById(Integer id) {
		// TODO Auto-generated method stub
		return null;
	}

}

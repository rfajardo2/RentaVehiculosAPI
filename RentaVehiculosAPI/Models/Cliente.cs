namespace RentaVehiculosAPI.Models
{
    public class Cliente
    {
        public int ID { get; set; }
        public string Nombre { get; set; }
        public string Email { get; set; }
        public string Telefonos { get; set; } // Guardar como una cadena separada por comas si son varios
        public string Direccion { get; set; }
        public string DocumentoIdentificacion { get; set; }
        public DateTime FechaRegistro { get; set; }
        public string Licencia { get; set; }
        public string Categoria { get; set; }
        public string Observacion { get; set; }
    }

}
